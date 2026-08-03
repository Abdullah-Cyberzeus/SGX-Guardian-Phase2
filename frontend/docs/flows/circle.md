# **Circle**

# **Flow Summary**

| Attribute | Detail |
| ----- | ----- |
| **Flow Name** | Circle Creation \+ Member Invite |
| **Primary Persona** | Sofia Reyes — Circle Admin / Security Team Lead |
| **Trigger** | Need to create a new trusted team group OR add a new member to an existing Circle |
| **Goal** | Create a Circle of Trust, invite team members via the most convenient method, confirm membership |
| **Entry Point** | Bottom nav → Network tab |
| **Exit Points** | Circle created with members invited / Member invite sent / Returned to Circles list |
| **Screens Involved** | NW-01, NW-02, NW-03, NW-04, NW-05, NW-06, NW-09, NW-10, NW-11, NW-12, NW-13 |
| **Estimated Completion Time** | 1–3 minutes (happy path) |
| **Complexity** | Medium — certificate generation async, 3 invite methods, confirmation states |
| **Frequency** | Weekly for Sofia — when onboarding new team members or creating project-specific Circles |

---

## **Happy Path — Mermaid Diagram**

Create Circle → Invite via Share Link → Member joins

flowchart TD
 A(\[Sofia opens Network tab\]) \--\> B\[NW-01 Circles List\\nEmpty or existing circles\]
 B \--\> C\[Tap \+ Create button\]
 C \--\> D\[NW-02 Create Circle Form\\nEnter name \+ description\]
 D \--\> E\[Sofia types Circle name:\\nIncident Response Team\]
 E \--\> F\[Tap Create Circle\]
 F \--\> G\[ POST /api/circles\\nCertificate Authority generated\\nCircle network initialized\]
 G \--\> H\[NW-03 Loading\\nInitializing Circle network...\]
 H \--\> I\[ NW-06 Circle Detail\\nMembers Tab — Sofia listed as Owner\]
 I \--\> J\[Tap Invite Member\]
 J \--\> K\[NW-09 Invite Modal\\nShare Link tab shown by default\]
 K \--\> L\[NW-10 Share Link Tab\\nInvite code \+ shareable URL displayed\]
 L \--\> M\[Tap Share Invite\]
 M \--\> N\[ Native browser share sheet\\niOS/Android share options appear\]
 N \--\> O\[Sofia shares link via\\nWhatsApp / Email / SMS\]
 O \--\> P\[ Toast: Invite link shared\]
 P \--\> Q(\[Returns to NW-06\\nMembers Tab\\nPending invite shown\])

---

## **Full Flow With All Branches**

flowchart TD
 %% Entry
 START(\[Sofia opens Network tab\]) \--\> NW01\[NW-01 Circles List\]

 NW01 \--\> EXISTING{Existing circles?}
 EXISTING \-- Yes \--\> NW01\_LIST\[Shows circle cards\\nwith member count \+ online status\]
 EXISTING \-- No \--\> NW01\_EMPTY\[Empty state\\nNo circles yet\\nCreate your first Circle CTA\]

 NW01\_LIST \--\> CHOICE{Sofia's goal}
 NW01\_EMPTY \--\> CHOICE

 CHOICE \-- Create new Circle \--\> CREATE
 CHOICE \-- Invite to existing Circle \--\> NW06\_EXIST\[Tap existing Circle\\nNW-06 Circle Detail → Members tab\]
 NW06\_EXIST \--\> INVITE\_MODAL

 %% Create Circle Flow
 CREATE\[Tap \+ Create\] \--\> NW02\[NW-02 Create Circle Form\]
 NW02 \--\> FORM\_FILL\[Sofia enters:\\nCircle Name required\\nDescription optional\]
 FORM\_FILL \--\> WHAT\_IS{Tap What is a Circle?}
 WHAT\_IS \-- Yes \--\> EXPLAINER\[Expandable explainer\\nplain language description\]
 EXPLAINER \--\> FORM\_FILL
 WHAT\_IS \-- No / continues \--\> SUBMIT

 SUBMIT\[Tap Create Circle\] \--\> VALIDATE{Form valid?}
 VALIDATE \-- Name empty \--\> VAL\_ERR\[ Inline error\\nCircle name is required\]
 VAL\_ERR \--\> FORM\_FILL
 VALIDATE \-- Valid \--\> API\_CREATE\[ POST /api/circles\\nname \+ description\]

 API\_CREATE \--\> NW03\[NW-03 Loading State\\nInitializing Circle network...\\nGenerating Certificate Authority\]
 NW03 \--\> CREATE\_RESULT{Result}
 CREATE\_RESULT \-- Success \--\> NW06\[NW-06 Circle Detail\\nLands on Members tab\\nSofia listed as Owner\]
 CREATE\_RESULT \-- Error \--\> CREATE\_ERR\[Error screen\\nFailed to create Circle\\nRetry / Cancel\]
 CREATE\_ERR \--\> NW02

 %% Invite Member Flow
 NW06 \--\> INVITE\_BTN\[Tap Invite Member\\nfull-width teal button\]
 INVITE\_BTN \--\> INVITE\_MODAL\[NW-09 Invite Modal\\nDefault: Share Link tab\]

 INVITE\_MODAL \--\> INVITE\_CHOICE{Invite method}

 %% Method 1 — Share Link (Default)
 INVITE\_CHOICE \-- Share Link tab \--\> NW10\[NW-10 Share Link Tab\\nInvite code displayed\\nShareable URL shown\]
 NW10 \--\> SHARE\_ACTION{Sofia's action}
 SHARE\_ACTION \-- Tap Copy Code \--\> COPY\_CODE\[ Copy invite code to clipboard\\n Toast: Code copied\]
 SHARE\_ACTION \-- Tap Copy Link \--\> COPY\_LINK\[ Copy full URL to clipboard\\n Toast: Link copied\]
 SHARE\_ACTION \-- Tap Share Invite \--\> SHARE\_SHEET\[ Native browser share sheet\\niOS or Android\]
 SHARE\_ACTION \-- Record by email \--\> EMAIL\_RECORD\[Enter email address\\nTap Record\\n Invitation logged in system\]
 SHARE\_SHEET \--\> SHARED\[ Link shared via\\nSMS / Email / WhatsApp / etc\]
 COPY\_CODE \--\> CLOSE\_MODAL
 COPY\_LINK \--\> CLOSE\_MODAL
 SHARED \--\> CLOSE\_MODAL
 EMAIL\_RECORD \--\> CLOSE\_MODAL

 %% Method 2 — QR Code
 INVITE\_CHOICE \-- QR Code tab \--\> NW11\[NW-11 QR Code Tab\\nQR code generated \+ displayed\]
 NW11 \--\> QR\_ACTION{Sofia's action}
 QR\_ACTION \-- Show screen to invitee \--\> QR\_SCAN\[Invitee scans QR\\nwith their device\]
 QR\_ACTION \-- Tap Share QR Code \--\> QR\_SHARE\[ Native share sheet\\nQR image shared\]
 QR\_SCAN \--\> CLOSE\_MODAL
 QR\_SHARE \--\> CLOSE\_MODAL

 %% Method 3 — Search DIDs (Advanced)
 INVITE\_CHOICE \-- Search DIDs tab \--\> NW12\[NW-12 Search DIDs Tab\\nAdvanced method\\nDID explainer shown\]
 NW12 \--\> DID\_INPUT\[Sofia enters DID or user ID\\ne.g. did:guardian:sgx05-xyz\]
 DID\_INPUT \--\> DID\_SEARCH\[ GET /api/users/search?did=...\]
 DID\_SEARCH \--\> DID\_RESULT{Search result}
 DID\_RESULT \-- User found \--\> DID\_FOUND\[User profile shown\\nName \+ DID confirmed\]
 DID\_RESULT \-- Not found \--\> DID\_NOT\_FOUND\[ No user found\\nCheck DID and try again\]
 DID\_RESULT \-- Invalid format \--\> DID\_INVALID\[ Invalid DID format\\nHelper text shown\]
 DID\_NOT\_FOUND \--\> DID\_INPUT
 DID\_INVALID \--\> DID\_INPUT
 DID\_FOUND \--\> SEND\_INVITE\[Tap Send Invite\]
 SEND\_INVITE \--\> INVITE\_API\[ POST /api/circles/id/invites\\n{ did: target\_did }\]
 INVITE\_API \--\> INVITE\_RESULT{Result}
 INVITE\_RESULT \-- Sent \--\> INVITE\_SENT\[ Toast: Invite sent to user\]
 INVITE\_RESULT \-- Already member \--\> ALREADY\[ This user is already\\na member of this Circle\]
 INVITE\_RESULT \-- Error \--\> INVITE\_ERR\[ Failed to send invite\\nRetry\]
 INVITE\_SENT \--\> CLOSE\_MODAL
 ALREADY \--\> NW12

 %% Close modal \+ result
 CLOSE\_MODAL\[Modal dismissed\\nSwipe down or X button\] \--\> NW06\_UPDATED\[NW-06 Members Tab\\nPending invite shown OR\\nnew member listed\]

 %% Remove Member Sub-flow
 NW06\_UPDATED \--\> REMOVE{Sofia wants to\\nremove a member?}
 REMOVE \-- Yes \--\> NW13\[NW-13 Remove Member\\nConfirmation sheet\]
 NW13 \--\> REMOVE\_CONFIRM{Confirm remove?}
 REMOVE\_CONFIRM \-- Confirm \--\> REMOVE\_API\[ DELETE /api/circles/id/members/userId\]
 REMOVE\_CONFIRM \-- Cancel \--\> NW06\_UPDATED
 REMOVE\_API \--\> REMOVE\_RESULT{Result}
 REMOVE\_RESULT \-- Success \--\> TOAST\_REMOVE\[ Toast: Member removed\]
 REMOVE\_RESULT \-- Error \--\> ERR\_REMOVE\[ Failed to remove member\\nRetry\]
 TOAST\_REMOVE \--\> NW06\_UPDATED

---

## **Step-by-Step Narrative**

### **Step 1 — Circles List (NW-01)**

Sofia taps **Network** in the bottom nav. She sees her Circles list. If she has existing Circles, each is shown as a card: Circle name, member count, online count, and two quick-access buttons (Chat, Members).

If she has no Circles yet, an empty state is shown: a team icon, "No circles yet", and a **Create your first Circle** CTA button.

She taps **\+ Create** (top right) to start a new Circle.

---

### **Step 2 — Create Circle Form (NW-02)**

Sofia sees the Create Circle form:

* **Circle Name** (required) — text input, placeholder: "e.g. Incident Response Team"
* **Description** (optional) — multiline text area, placeholder: "What is this circle for?"
* A **Circle Network** info card explaining: *"Your Circle will use secure peer-to-peer communication. No internet required for Circle members to connect — works over WiFi, cellular, or satellite."*
* A **Create Circle** primary CTA button
* Four green checkmarks showing what will happen: Certificate Authority generated, Circle network configured, Guardian joins automatically, Network relay enabled

A subtle **"What is a Circle?"** link opens an expandable explainer for new users.

**Design note:** The four green checkmarks from the existing app are a strong trust signal — keep them in the redesign. They reduce uncertainty during the async creation step.

---

### **Step 3 — Loading State (NW-03)**

After tapping Create Circle, Sofia sees a loading state: *"Initializing Circle network... This may take a moment."*

**System actions happening in background:**

1. Certificate Authority (CA) generated for this Circle
2. Circle network configured with CA
3. Sofia's Guardian automatically joins as the first member
4. Network relay enabled for extended range

This typically takes 2–5 seconds. The loading state should show progress indicators, not just a spinner, so Sofia knows something is happening.

---

### **Step 4 — Circle Detail — Members Tab (NW-06)**

On success, Sofia lands on the newly created Circle's detail screen, defaulting to the **Members tab**. She sees herself listed as the Owner with her email and online status.

A large **Invite Member** button (teal, full-width) is prominently displayed at the top.

---

### **Step 5 — Invite Modal — Share Link (NW-09, NW-10)**

Sofia taps **Invite Member**. A bottom sheet modal slides up showing the invite options with **Share Link** as the default active tab.

She sees:

* **Invite Code:** `M1DXH8` — displayed prominently in a code block with a copy button
* **Shareable Link:** `https://sg-x-guardian.app/invite/M1DXH8` — with a copy button
* **Share Invite** — large teal button that triggers the native browser share sheet
* **Record an invitation** — email input \+ Record button to log the invite in the system

Sofia taps **Share Invite** → the iOS/Android native share sheet appears → she sends it via WhatsApp to her new contractor.

**Design note:** Share Link is the default because it's the most friction-free for the invitee — they just tap a link, no DID knowledge required. DID search is available as an "Advanced" option but should not be the default.

---

### **Step 6 — QR Code Method (NW-11)**

If Sofia and the invitee are in the same room, she switches to the **QR Code tab**. A QR code is displayed that encodes the invite link. The invitee scans it with their phone camera.

The QR code also shows the invite code (`M1DXH8`) in text below it — backup if scanning fails.

---

### **Step 7 — DID Search Method (NW-12) — Advanced**

For technically sophisticated users, the **Search DIDs tab** allows searching by Decentralized Identifier. An info panel explains: *"Search for users by their Decentralized Identifier (DID) to add them to your Circle. DIDs provide privacy-preserving authentication without revealing personal information."*

A tip at the bottom: *"Users need to have SG-X Guardian installed to join."*

---

### **Step 8 — Members Tab After Invite (NW-06 updated)**

After closing the invite modal, Sofia returns to the Members tab. She sees her invite listed as **Pending** until the invitee accepts. Once accepted, they appear as an active member with their online/offline status.

---

### **Remove Member Sub-flow**

Sofia can remove a member by tapping their card and selecting **Remove from Circle**. A confirmation bottom sheet appears: *"Remove \[Name\] from \[Circle\]? They will lose access to this Circle's chat, calls, and shared security data."*

A **Confirm** button (red/destructive) and **Cancel** button are shown. This prevents accidental removals.

---

## **Screen List**

| Step | Screen ID | Screen Name |
| ----- | ----- | ----- |
| 1 | NW-01 | Circles List |
| 2 | NW-02 | Create Circle Form |
| 3 | NW-03 | Create Circle Loading |
| 4 | NW-06 | Circle Detail — Members Tab |
| 5a | NW-09 | Invite Modal Container |
| 5b | NW-10 | Invite — Share Link Tab |
| 6 | NW-11 | Invite — QR Code Tab |
| 7 | NW-12 | Invite — Search DIDs Tab |
| 8 | NW-06 | Members Tab (updated with pending) |
| 9 | NW-13 | Remove Member Confirmation |

---

## **API / System Dependencies**

| Action | API Call | Failure Handling |
| ----- | ----- | ----- |
| Load circles | `GET /api/circles` | Empty state if none, error banner if API fails |
| Create circle | `POST /api/circles` | Error screen with retry |
| Generate CA | Auto on creation | Non-recoverable error → must retry circle creation |
| Send invite (DID) | `POST /api/circles/:id/invites` | Error toast \+ retry |
| Search DID | `GET /api/users/search?did=` | Not found state |
| Remove member | `DELETE /api/circles/:id/members/:userId` | Confirmation \+ error toast |
| Load members | `GET /api/circles/:id/members` | Stale data with offline banner |

---

## **Design Notes**

| \# | Note |
| ----- | ----- |
| DN-01 | **Share Link is the default invite tab** — not DID Search. DID Search is labelled "Advanced" and placed last. |
| DN-02 | The **Invite Code** (`M1DXH8`) must be displayed in a large, bold, monospace font — it needs to be readable at arm's length or when showing the screen to someone else. |
| DN-03 | The **Remove Member confirmation sheet** must explain consequences clearly: "They will lose access to this Circle's chat, calls, and shared security data." Destructive actions need context. |
| DN-04 | **Certificate Authority generation** is a significant technical event — the loading state should communicate its importance without being intimidating. Use plain language: *"Setting up your Circle's secure network..."* |
| DN-05 | The **4 green checkmarks** on the Create Circle form (existing feature) are a strong design element — they reduce anxiety about the async creation step. Keep them. |
| DN-06 | Pending invites in the Members tab should show a **"Pending"** badge with a subtle amber color so Sofia knows the invite was sent but not yet accepted. |
| DN-07 | The QR code must be **large enough to scan** — minimum 200×200px in the UI, with adequate white space around it. |

---

## **Edge Cases**

| Edge Case | Handling |
| ----- | ----- |
| Circle name already taken by this user | Inline error: "You already have a Circle with this name" |
| CA generation times out | Error with retry: "Circle setup is taking longer than expected. Try again." |
| Invitee already in Circle | Error toast: "This user is already a member of this Circle" |
| Invite link expires | Invitee sees expired link message \+ option to request a new one |
| No network when creating Circle | Disable Create button, show: "You need to be connected to your Guardian to create a Circle" |
| DID search returns multiple results | Show list of matching users with DID \+ name — Sofia selects the right one |
| User removes themselves (owner) | Block with message: "You can't remove yourself as the Circle owner. Transfer ownership first." |

