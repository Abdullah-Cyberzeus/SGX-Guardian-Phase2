# Issue Backlog

## Resolved

### NodeB read receipts stayed delivered after NodeA read messages
Fixed board-to-board read receipts by carrying the reader node ID with receipt pushes, trusting the reader DID first with node ID fallback, updating direct messages by message ID when peer identity mapping differs, and emitting an updated message status event after the receipt is applied.

### Attestation counters showed zero on board
Fixed the Circle topology attestation summary by merging verified peer data onto CoT nodes through multiple aliases, including node ID, peer ID, DID, device/display name, and IP fields. Attested, pending, and failed counts now reflect the merged node state.

### NodeB IP address hidden in group info
Fixed the group members sheet so the local member row uses the local Guardian/admin IP fallback, not only the circle owner row. NodeB now shows its own IP in group info.

### Chat opened at the top instead of the latest message
Fixed chat opening behavior by scrolling the actual message container to the bottom after messages render, with a follow-up animation-frame scroll for loaded content.

### Vault History button shown in the right-side file panel
Removed the History action and download-history dialog from the Vault file detail panel.

### Expired or revoked Vault files could still be sent
Blocked expired and revoked Vault files from Secure Transfer selection and queueing, disabled `Send to peer` for unavailable files, and added backend XFER checks so direct API calls cannot send expired or revoked Vault records.

### Member Vault screen overlapped on narrower layouts
Adjusted the Vault file browser breakpoints so secondary columns and the split detail panel appear only on wider screens, and made file metadata rows stack on small screens.

### TLS admin circle creation failed origin verification
Updated auth middleware so same-origin unsafe requests can validate against the request URI authority when the `Host` header is absent, which covers HTTPS/HTTP2 admin requests under `SGX_ADMIN_TLS_ENABLED=true`.

## Notifications and Alerts

### Notification alerts do not open when clicked
Clicking a notification alert does not navigate to or open the related alert details. Users should be taken directly to the relevant alert, device, chat, or notification context when they select the alert.

### Notifications display IP address instead of device name or saved contact
Notifications currently show an IP address where a friendly device name or saved contact name should appear. Notifications should prefer saved contact names first, then known device names, and only fall back to IP address when no friendly label is available.

## File Transfer

### DID displayed in file download history
The file download history displays a DID instead of a recognizable device name or saved contact. Download history entries should resolve sender and receiver identity to a saved contact or device name when available.

## Calls

### Group call screen issue
The group call screen does not always show expected features to the calling end. Investigate missing or inconsistent controls during group calls and ensure the caller sees the full intended feature set.

### Camera feature appears in audio call
Audio-only calls expose or show camera functionality. The camera control should be hidden or disabled for audio calls unless the user explicitly switches to video.

### Group call stability issues
Group calls fluctuate between working and causing issues. Investigate unstable group call behavior, including call setup, participant state sync, controls, media handling, and UI state changes.

## Network Discovery

### Remove "Add Task" button from Scheduled tab
The Scheduled tab in Network Discover includes an "Add Task" button that should not be available there. Remove the button from that tab to match the intended workflow.

## Baselines and Attestation

### Creating a new baseline tampers secure elements
Creating a new baseline appears to tamper with or modify secure elements unexpectedly. Baseline creation should not corrupt, reset, or alter secure element state unless explicitly intended and confirmed.

### Remove guardian binary hash from Boot Status
The Boot Status view currently shows the guardian binary hash. Remove this field from the Boot Status UI.

### Baseline history is not stored
The system does not store history for baselines. Baseline creation and changes should be retained so users can review prior baseline state and compare changes over time.

## Sessions

### Increase logout session timeout
The current logout session timeout is 20 minutes, which is too short. Increase the session duration to reduce unnecessary logouts during normal use.

## DID and Node Management

### No button to reactivate DID
There is currently no available button or flow to reactivate a deactivated DID. Add a clear reactivation action where users manage DID status.

### Add DID reactivation button from nodes
Nodes should provide a way to reactivate a DID directly from the node management context. The action should be visible when a DID is deactivated and should update the node state after reactivation.

### Message behavior differs when DID is deactivated
Messaging behaves inconsistently when a DID is deactivated, with different behavior between group chats and individual chats. Define the expected behavior for deactivated DIDs and apply it consistently across chat types.

## Credentials and Policy Management

### Remove "Issue VC" button from Credentials
The Credentials screen includes an "Issue VC" button that should be removed from the frontend.

### Remove "Copy" button from Policy Management
The Policy Management screen includes a "Copy" button that should be removed from the frontend.

## Device Settings

### Remove offline buttons from device settings
The frontend device settings screen includes offline buttons that should no longer be shown. Remove these buttons from the device settings UI.
