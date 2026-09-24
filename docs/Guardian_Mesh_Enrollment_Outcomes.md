# SGX Guardian — What We Get After the Mesh Circle Plan

This document explains, in simple words, what will change in SGX Guardian after we finish the plan in
[Guardian_Mesh_Enrollment_Complete_Plan.md](Guardian_Mesh_Enrollment_Complete_Plan.md).

It answers three questions:

1. **What will change** in the project?
2. **What will be new**?
3. **What will we achieve**?

---

## 1. The short version

**Today:** SGX Guardian works like a small, fixed team of three devices. One device, called `nodeA`, is always the boss. The other devices cannot even show their web screen until the boss gives them a certificate.

**After the plan:** SGX Guardian works like a real product that can grow.

- Any Guardian can be switched on and set up from the browser.
- The user decides whether to **start a new group (Circle)** or **join an existing one**.
- A Guardian can join a group on the same local network, or a group in another country.
- There is no limit of three devices.
- Private keys never leave the device.

---

## 2. Simple words used in this document

| Word | Simple meaning |
|---|---|
| **Guardian** | One SGX device (a board or a box) |
| **Circle** | A trusted group of Guardians. Members of a Circle trust each other |
| **CA** (Certificate Authority) | The Guardian that gives "ID cards" (certificates) to new members of its Circle |
| **Certificate** | A digital ID card. It proves "this Guardian belongs to this Circle" |
| **Private key** | A secret that proves who a Guardian is. It must never leave the device |
| **Nebula** | The private network that connects Guardians to each other, even across the internet |
| **Lighthouse** | A public server that helps Guardians find each other on the internet |
| **Rendezvous** | A public meeting point where a new Guardian can reach a CA that is far away |
| **Attestation** | A check that a device is real, untouched, and running the right software |
| **Join code** | A one-time code (or QR code) that the CA owner gives to a new Guardian so it can join safely |
| **LAN** | The local network (same office, same home Wi-Fi) |
| **WAN** | The internet (a different building, city or country) |

---

## 3. Before and after: at a glance

| Topic | Today | After the plan |
|---|---|---|
| Who is the boss (CA)? | Always the device named `nodeA` | Whichever Guardian the user chooses with **Create Mesh Circle** |
| Number of Guardians | Built around 3 (`nodeA`, `nodeB`, `nodeC`) | Any number (up to about 250 per Circle by default, more if configured) |
| Web screen (frontend) | Only works **after** the device gets a certificate | Works **right after power-on** |
| First setup | Done with command-line and config files | Done in the browser with clear screens |
| Choosing a group | Not possible: there is only one fixed group | User can **Create** a Circle or **Join** a Circle |
| Many groups on one network | Not supported | Supported: the user sees a list and picks one |
| Joining from another country | Possible through the cloud server, but fixed to one group | Clean, guided flow with a join code |
| Private key of new member | **Made by the boss and sent over the network** | **Made on the device and never sent anywhere** |
| Checking the boss is real | Trusted by IP address only | Checked by a digital signature and fingerprint |
| Checking the new device is real | Not checked when joining | Device health and identity are checked before joining (attestation) |
| Approving a new member | Admin edits a YAML file on the boss device | Admin taps **Approve** or **Reject** in the web app |
| Setup error | The program stops (crashes out) | The screen shows the problem, with **Retry** and **Reset** buttons |
| Removing a member | Partly supported | One click: removes the member and blocks it on the network |
| If the boss device is lost | The whole group must be rebuilt | Backup and restore; optional second CA |

---

## 4. What will change in the project

### 4.1 Changes in the backend (Rust)

- **No more "nodeA is the boss" rule.** About 700 places in the code that say `nodeA` will be replaced by one simple question: "Is this device the CA of its Circle?"
- **No more fixed group name and fixed network address.** Each Circle gets its own ID and its own network range.
- **No more fixed ports per device name.** Every Guardian uses normal ports from its config file, so a 4th, 5th or 100th device works the same way.
- **Startup is split into two parts:**
  1. **Local start.** The device starts its security chip, identity and web screen. This always works, even with no Circle.
  2. **Mesh start.** The Nebula network, calls, chat, file transfer and so on start **only after** the device has joined a Circle.
- **Joining is rebuilt** with a new, safer protocol (Enrollment v2).
- **The old YAML approval files** are replaced with a proper request list that the web app can show.

### 4.2 Changes in the cloud server (`sgx-broker`)

- It becomes a **Rendezvous** point: a meeting place for new Guardians and far-away CAs.
- It **only passes signed, public messages.** It never sees or carries private keys.
- It **cannot change** messages without being detected.
- Each Circle gets **its own Lighthouse** on the server, so different Circles stay separate.

### 4.3 Changes in the frontend (web app)

- A new **Setup** area appears when a Guardian is not yet in a Circle.
- The existing **Pending Approvals** screen shows more useful details about each request.
- The dashboard shows a **Mesh card**: Circle name, role, CA, certificate expiry and network status.

### 4.4 Existing installations

- Current `nodeA` / `nodeB` / `nodeC` setups **keep working**.
- On upgrade, the system **automatically** turns the old setup into the new format. Nobody needs to set it up again.

---

## 5. What will be new

### 5.1 New screens for the user

| Screen | What the user sees and does |
|---|---|
| **Setup Choice** | "This Guardian is not in a Circle yet." Two buttons: **Create Mesh Circle** and **Join Existing Circle** |
| **Create Circle** | Type a Circle name, press **Create**. The device becomes the CA of the new Circle |
| **Join: Local search** | The device searches the local network and shows a list of Circles found nearby |
| **Join: Remote (internet)** | Enter the server address and join code to join a Circle in another place |
| **Confirm CA** | Shows the CA's fingerprint so the user can be sure it is the right one |
| **Joining progress** | Live steps: key created → request sent → waiting for approval → certificate received → online |
| **Join failed** | Clear reason, with **Retry** and **Reset** buttons |
| **Join complete** | Shows Circle, CA, certificate status, device check status and network status |
| **Invite Guardian** (on the CA) | Creates a one-time join code and QR code to give to a new device |
| **Pending approvals** (on the CA) | Shows each request with ✔ / ✖ checks and **Approve** / **Reject** buttons |

### 5.2 New features

- **Create Mesh Circle:** any Guardian can start its own trusted group.
- **Join Existing Circle:** any Guardian can join a group, nearby or far away.
- **Join codes and QR codes:** a safe and easy way to invite a new device.
- **Many Circles on one network:** each one is shown separately and kept separate.
- **Device check before joining:** the CA can refuse devices with unknown or changed software.
- **Automatic certificate renewal:** certificates renew before they expire.
- **Remove a Guardian:** it is removed from the Circle and blocked from the network at once.
- **Leave a Circle:** a member can leave and go back to setup mode.
- **CA backup and restore:** the Circle can survive the loss of the CA device.
- **Second CA (later phase):** a Circle can have a backup CA.
- **Circle rules:** the CA owner can decide who may join and what members are allowed to do.

---

## 6. How it will work: simple stories

### Story 1: Start a new Circle

1. Ali switches on a new Guardian.
2. He opens its web page. The page shows **"Not in a Circle"**.
3. He clicks **Create Mesh Circle** and types the name "Office-Lahore".
4. The Guardian becomes the CA of "Office-Lahore" and goes **Online**.

### Story 2: Join a Circle in the same office

1. Sara switches on a second Guardian in the same office.
2. She clicks **Join Existing Circle**. The page shows "Office-Lahore" (and any other Circles in the office).
3. Ali opens **Invite Guardian** on his device and shows a QR code.
4. Sara scans it. Her device creates its own key, asks to join, and is checked.
5. It is approved automatically (or Ali taps **Approve**). Sara's Guardian is now **Online**.

### Story 3: Join a Circle in another country

1. A Guardian in Pakistan wants to join a Circle whose CA is in the USA.
2. The local search finds nothing, so the user clicks **Search via internet**.
3. The user enters the server address and the join code sent by the USA admin.
4. The request goes through the public server to the USA CA. The USA CA checks it and signs it.
5. The Pakistan Guardian receives its certificate and joins the private network.
6. After that, Pakistan and USA devices talk **directly**. Traffic does **not** go through the CA.

---

## 7. What we will achieve

### 7.1 For the product

- **From a demo setup to a real product.** SGX Guardian is no longer a fixed 3-device system.
- **Grows with the customer.** Add as many Guardians as needed, one by one.
- **Works across sites and countries.** One Circle can include offices in Pakistan, the USA, Europe and more.
- **Many customers or teams on one network.** Different Circles stay separate and do not trust each other.

### 7.2 For security

- **Private keys stay on the device.** This fixes the biggest security gap we have today.
- **No fake CA.** A device cannot be tricked into joining a fake group on the network.
- **No fake devices.** The CA can check that a new device is real and healthy before trusting it.
- **Safe cloud server.** The public server helps with connections but cannot read keys or change results.
- **Fast blocking.** A removed or stolen device is blocked at the network level.
- **Full audit trail.** Every step (create, join, approve, reject, remove) is logged.

### 7.3 For users and support

- **Setup in the browser.** No command-line or file editing is needed.
- **Clear status.** The user always sees where the device is: not set up, joining, waiting, or online.
- **No silent crashes.** Problems are shown on screen with a fix option.
- **Easy invites.** Share a QR code, and the new device joins.

### 7.4 For reliability

- **The CA is not a bottleneck.** After joining, devices talk to each other directly.
- **If the CA goes offline,** existing members keep working. Only new joins wait.
- **If the internet server goes offline,** local devices keep working. Only remote joins wait.
- **Backup and second CA** protect the Circle if the CA device is lost.

### 7.5 For the development team

- **Cleaner code.** Roles come from one place (the Mesh Profile) instead of 700 hard-coded names.
- **Easier testing.** Setup, joining and network startup are separate parts, and each can be tested alone.
- **Safer changes.** A test stops anyone from adding `"nodeA"` back into the code.

---

## 8. Delivery in steps (milestones)

| Milestone | What you can see and demo |
|---|---|
| **M1: Safe and bigger** | 5 or more Guardians work together. No private keys are sent over the network |
| **M2: Setup in the browser** | New device → open browser → Create Mesh Circle → online |
| **M3: Join on the local network** | Two Circles in one office. A new device picks one and joins with a QR code |
| **M4: Trusted join** | A device with unknown software is refused, and accepted after the admin trusts it |
| **M5: Join from another country** | A Pakistan Guardian joins a USA Circle and makes a direct call |
| **M6: Full lifecycle** | Renew, remove, backup and restore the CA, second CA |

---

## 9. What will not change

- **Calls, group calls, chat, file transfer, vault, alerts, smart home and threat detection** work the same as today. They simply start after the device joins a Circle.
- **Comms Circles** (chat groups) stay as they are. The new **Mesh Circle** is a different thing: it is the trusted device network.
- **Existing installations** are upgraded automatically.

---

## 10. In one sentence

After this plan, **any SGX Guardian can be switched on, opened in a browser, and safely create or join a trusted Circle on the local network or across the world, with no limit of three devices and without its private key ever leaving the device.**
