# Issue Backlog

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

### Attestation always shows zero
Attestation status or score always displays `0`, even when attestation data should be available. Investigate whether this is a backend calculation, data mapping, or frontend rendering issue.

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

### NodeB read receipts not working
Read receipts for NodeB are not functioning correctly. Investigate message receipt generation, delivery, sync, and UI rendering for NodeB conversations.

### NodeB IP address hidden in group info
NodeB's IP address is hidden in group information. Group info should show the expected NodeB network identity details when the user has permission to view them.

## Credentials and Policy Management

### Remove "Issue VC" button from Credentials
The Credentials screen includes an "Issue VC" button that should be removed from the frontend.

### Remove "Copy" button from Policy Management
The Policy Management screen includes a "Copy" button that should be removed from the frontend.

## Device Settings

### Remove offline buttons from device settings
The frontend device settings screen includes offline buttons that should no longer be shown. Remove these buttons from the device settings UI.
