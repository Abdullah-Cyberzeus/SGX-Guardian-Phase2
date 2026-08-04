# Guardian Chat Module: Complete Testing Plan

This document is strictly focused on testing the Chat features. It includes the exact `curl` commands to execute the features and step-by-step instructions on how to verify that each action was successful across both nodes.

**Prerequisites:** 
- Node A (`192.168.100.1`) and Node B (`192.168.100.2`) are running.
- Both nodes have unique identities (`did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE` and `did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa`).
- Both nodes appear in each other's `trusted_peers.json`.

---

## 1. Sending a Text Message

Test sending a standard text message from Node A to Node B.

### Step 1: Execute on Node A
```bash
curl -X POST http://localhost:8443/api/v1/chat/send \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_did": "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa",
    "content": "Hello Node B! This is an E2E test message.",
    "attachment_id": null,
    "is_group": false
  }'
```
> [!NOTE]
> Save the `message_id` that is returned in the JSON response. You will need it for the read receipt test.

### Step 2: Verify it Worked
**On Node A:**
- Run `journalctl -u sgx-guardian -f` and watch for: `💬 Chat: target peer found — sending to <NODE_B_IP>`
- Verify the local file `/var/lib/sgx-guardian/chat/p2p/<PEER_DID>.jsonl` was created and contains the message.

**On Node B:**
- Run `journalctl -u sgx-guardian -f` and watch for: `💬 Chat message received from did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE`
- Run the history API to verify Node B saved it:
  ```bash
  curl -X GET "http://localhost:8443/api/v1/chat/history?peer_did=did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  ```
- The JSON response should show the message with `"status": "delivered"`.

---

## 2. Sending a Read Receipt

Simulate Node B opening the chat UI, seeing the message, and telling Node A it was read.

### Step 1: Execute on Node B
Use the `message_id` you saved from Test #1.
```bash
curl -X POST http://localhost:8443/api/v1/chat/read \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": "<MESSAGE_ID_FROM_TEST_1>",
    "original_sender_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
  }'
```

### Step 2: Verify it Worked
**On Node A (The original sender):**
- **Log Check:** Run `journalctl -u sgx-guardian -f`. You should see a log: `💬 Chat: Read receipt received for message <MESSAGE_ID>`.
- **API Check:** Fetch the history on Node A:
  ```bash
  curl -X GET "http://localhost:8443/api/v1/chat/history?peer_did=did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa"
  ```
  Look at the message in the JSON array. The `"status"` field should have changed from `"delivered"` to `"read"`.

---

## 3. Sending an Image / Attachment

Test the encrypted file transport. This requires uploading on Node A, sending the ID in a message, and downloading it on Node B.

### Step 1: Upload the file (Execute on Node A)
Create a dummy file and upload it to the local API:
```bash
echo "Secret attachment content" > /tmp/secret.txt

curl -X POST http://localhost:8443/api/v1/chat/upload \
  -F "file=@/tmp/secret.txt"
```
> [!NOTE]
> Save the `attachment_id` returned in the response.

### Step 2: Send the Message (Execute on Node A)
```bash
curl -X POST http://localhost:8443/api/v1/chat/send \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_did": "did:guardian:3udaKaaqBaN9SsrdtJAtBiDkz8FtHosj9DpPFkS8wXYa",
    "content": "Check out this secret file!",
    "attachment_id": "<ATTACHMENT_ID_FROM_STEP_1>",
    "is_group": false
  }'
```

### Step 3: Verify & Download (Execute on Node B)
First, verify Node B received the message by checking the history:
```bash
curl -X GET "http://localhost:8443/api/v1/chat/history?peer_did=did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
```
The message should contain the `attachment_id`. Now, verify Node B can download and decrypt the file over the P2P network:
```bash
curl -O -J http://localhost:8443/api/v1/chat/download/<ATTACHMENT_ID_FROM_STEP_1>
cat secret.txt
```
* **Validation:** The output of `cat` should perfectly match `"Secret attachment content"`.

---

## 4. History Synchronization (Offline Testing)

Verify that if Node B goes offline, it can fetch missed messages from Node A when it reconnects.

### Step 1: Simulate Offline
Stop the daemon on Node B:
```bash
systemctl stop sgx-guardian
```

### Step 2: Send messages into the void (Execute on Node A)
Send 3 new messages to Node B using the `api/v1/chat/send` curl command from Test #1.
* **Validation on Node A:** Because Node B is offline, Node A's API will return a success response but the messages will have `"status": "queued"` or `"sent"` rather than `"delivered"`.

### Step 3: Reconnect and Sync (Execute on Node B)
Start Node B back up:
```bash
systemctl start sgx-guardian
```
Since you are testing via `curl` and not the frontend UI, you must manually trigger the sync process to fetch missed messages:
```bash
curl -X POST http://localhost:8443/api/v1/chat/sync
```

### Step 4: Verify it Worked
**On Node B:**
Fetch the history to ensure the 3 missed messages were successfully downloaded and saved:
```bash
curl -X GET "http://localhost:8443/api/v1/chat/history?peer_did=did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE"
```
* **Validation:** All 3 messages should be present in Node B's history array, in the exact chronological order they were sent.

---

## 5. Group Chat Messaging

Test sending a broadcast message to all verified peers in the Circle of Trust with unified group history and per-member read receipt tracking.

### Step 1: Send Group Message (Execute on Node A)
Set `"is_group": true` and use the circle identifier (e.g., `"circle-1234"`) as the `recipient_did`:
```bash
curl -X POST http://localhost:8443/api/v1/chat/send \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_did": "circle-1234",
    "content": "Hello Dev Team! This is a secure circle broadcast.",
    "is_group": true
  }'
```
> [!NOTE]
> Save the `message_id` returned in the JSON response.

### Step 2: Verify Group History on Node A (Sender)
Query history on Node A using `group_id=circle-1234`:
```bash
curl -X GET "http://localhost:8443/api/v1/chat/history?group_id=circle-1234"
```
* **Validation:** The message is saved in `/var/lib/sgx-guardian/chat/group/circle-1234.jsonl` with `"read_by": []` and `"status": "pending"`.

### Step 3: Verify Group History on Node B (Recipient)
Query group history directly on Node B using `group_id=circle-1234`:
```bash
curl -X GET "http://localhost:8443/api/v1/chat/history?group_id=circle-1234"
```
* **Validation:** Node B receives the message via gRPC fan-out and stores it under the shared group thread (`/var/lib/sgx-guardian/chat/group/circle-1234.jsonl`) with `"status": "delivered"`.

### Step 4: Mark Group Message as Read (Execute on Node B)
Simulate Node B reading the group message:
```bash
curl -X POST http://localhost:8443/api/v1/chat/read \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": "<MESSAGE_ID_FROM_STEP_1>",
    "original_sender_did": "did:guardian:C2txwUBkHG5GukHRgvbZQqvxtv7CNkNDvdRAQfx9VQkE",
    "group_id": "circle-1234"
  }'
```

### Step 5: Verify Per-Member Read Receipt Tracking (Execute on Node A)
Re-query the group history on Node A:
```bash
curl -X GET "http://localhost:8443/api/v1/chat/history?group_id=circle-1234"
```
* **Validation:** Node B's DID will be added to the message's `"read_by": ["did:guardian:3uda..."]` array. Status remains `"delivered"` until **all** circle members have read it.