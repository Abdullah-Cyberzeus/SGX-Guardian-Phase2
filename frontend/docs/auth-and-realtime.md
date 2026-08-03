# **Auth and Realtime**

---

**Document:** Auth Flow \+ Real-time Requirements **Project:** SG-X Guardian Mobile Web App **For:** Cyberzeus Engineering Team **From:** Lightning Leap Analytics Pvt. Ltd. **Date:** March 2026

---

## **1\. AUTHENTICATION FLOW**

### **Tech Stack**

* **Auth provider:** Supabase Auth  
* **Session storage:** Supabase JS client handles this automatically in localStorage under `sb-{project_ref}-auth-token`  
* **Server:** Supabase Edge Function (Hono) using `SUPABASE_SERVICE_ROLE_KEY` for admin operations

---

### **Flow A — Email/Password Sign Up (New User)**

1\. User fills Create Account form (email, password, name)  
   └── OB06AccountSetup.tsx

2\. Frontend calls → POST /auth/signup  
   Request: { email, password, name }  
     
3\. Server uses SUPABASE\_SERVICE\_ROLE\_KEY to call:  
   supabase.auth.admin.createUser({  
     email,  
     password,  
     email\_confirm: true,   ← bypasses email verification  
     user\_metadata: { name }  
   })

4\. Server returns → { user: { id, email } }

5\. Frontend immediately calls client-side:  
   supabase.auth.signInWithPassword({ email, password })  
     
6\. Supabase returns session:  
   {  
     access\_token: "JWT...",  
     refresh\_token: "...",  
     expires\_at: 1234567890,  
     user: { id, email, user\_metadata: { name } }  
   }

7\. AuthContext stores session in React state  
   Supabase JS client stores it in localStorage automatically

8\. Frontend navigates → /onboarding/did

---

### **Flow B — Email/Password Login (Returning User)**

1\. User fills Login form (email, password)  
   └── LoginScreen.tsx or OB06AccountSetup.tsx (Log In tab)

2\. Frontend calls client-side:  
   supabase.auth.signInWithPassword({ email, password })

3\. On success → session returned (same shape as above)

4\. Frontend sets localStorage key: sgx\_onboarded \= "1"

5\. Navigate → /home

---

### **Flow C — Cylenium OAuth (Currently Simulated)**

CURRENT STATE (simulated, not real OAuth):  
1\. User taps "Continue with Cylenium"  
2\. Frontend shows loading state for \~2 seconds  
3\. Checks localStorage "sgx\_cylenium\_scenario":  
   \- If "fail" → shows error toast, returns to form  
   \- Otherwise → sets localStorage "sgx\_cylenium\_connected" \= "1"  
                → navigate to /home

NEEDS TO BE IMPLEMENTED BY CYBERZEUS:  
1\. User taps "Continue with Cylenium"  
2\. Frontend redirects to Cylenium OAuth URL  
   (Cyberzeus to provide this URL)  
3\. User authenticates on Cylenium  
4\. Cylenium redirects back to SGX app with OAuth code  
5\. Frontend exchanges code for Cylenium token  
6\. Frontend calls → POST /integrations/cylenium/connect  
   Request: { oauthToken }  
7\. Backend verifies token with Cylenium API  
8\. Backend links Cylenium account to Guardian  
9\. Sets sgx\_cylenium\_connected flag  
10\. Navigate → /home (or continue onboarding)

---

### **Session Management**

| Scenario | What Happens |
| ----- | ----- |
| App opens — session exists | Splash screen detects session → `/home` |
| App opens — no session, onboarded before | Splash detects `sgx_onboarded` in localStorage → `/login` |
| App opens — never onboarded | Splash → `/onboarding` |
| Token expires (typically 1h) | Supabase auto-refreshes using refresh\_token |
| Token refresh fails | `onAuthStateChange` fires `TOKEN_REFRESH_FAILED` → `signOut()` → splash redirects to `/login` |
| User logs out | `supabase.auth.signOut()` → clears session \+ `sgx_onboarded` from localStorage → `/login` |

---

### **localStorage Keys (Frontend Only)**

These are used by the frontend only — backend does not need to read them:

| Key | Value | Set By | Meaning |
| ----- | ----- | ----- | ----- |
| `sgx_onboarded` | `"1"` | OB09, Login success | Has user completed onboarding? |
| `sgx_cylenium_connected` | `"1"` | Cylenium OAuth success | Is Cylenium Cloud linked? |
| `sgx_cylenium_scenario` | `"fail"` | Dev testing only | Override Cylenium flow outcome |
| `sb-{ref}-auth-token` | JSON | Supabase JS client (auto) | Session tokens — DO NOT manually read/write |

---

### **Protected Routes**

Currently the app has no route-level auth guard middleware. The splash screen (`/`) acts as the entry gatekeeper. For production, Cyberzeus should note:

* All API endpoints under `/guardian/*`, `/alerts/*`, `/devices/*`, `/circles/*`, `/user/*` require a valid Supabase `access_token` in the Authorization header  
* The frontend sends: `Authorization: Bearer {session.access_token}` on every request  
* If the backend receives an invalid or expired token → return `401`  
* The frontend `AuthContext` will catch the 401, attempt token refresh, and retry once before logging the user out

---

## **2\. DID (Decentralized Identifier)**

### **Current Implementation**

The DID is currently generated client-side deterministically from `user.id`:

// From useCurrentUser.ts  
const did \= \`did:cervais:0x${user.id.replace(/-/g, '').padEnd(64, '0')}\`;

This means the DID changes if the user ID changes. For production:

**Cyberzeus needs to:**

1. Generate a proper DID on user creation using the `did:cervais` method  
2. Store it in the `users` table under a `did` column

Set it on the Supabase `user_metadata` after creation:  
 user\_metadata: { name, did: "did:cervais:0x..." }

3.   
4. Return it from `GET /user/did`

**Short Alias** (e.g. `TX-042-MR`) — currently hardcoded in mock data. In production, Cyberzeus should generate this as a deterministic 3-segment human-readable identifier from the DID and store it alongside the DID.

**QR Code** — generated client-side using `qrcode.react` from the DID string. No backend action needed.

---

## **3\. REAL-TIME REQUIREMENTS**

### **What Must Be Real-Time**

The following data changes in the real world and must update in the UI without the user refreshing:

---

#### **Guardian Device Status**

**What changes:** online/offline, battery %, signal strength, peer count **Why it matters:** The dashboard hero card shows Guardian status — if it goes offline, the user must see the offline banner immediately **Recommended:** WebSocket connection from the Guardian hardware device → Supabase → frontend **Update frequency:** Battery \+ signal every 30 seconds. Online/offline immediately on change.

---

#### **New Security Alerts**

**What changes:** New alert created when Guardian detects a threat **Why it matters:** Marcus needs to see HIGH alerts the moment they fire — this is the core use case **Recommended:** Supabase Realtime subscription on `alerts` table INSERT event **Update frequency:** Immediate — must push within seconds of creation

---

#### **Alert Status Changes**

**What changes:** Alert goes from Active → Archived or Active → Blocked **Why it matters:** If another team member resolves an alert, others should see it updated **Recommended:** Supabase Realtime subscription on `alerts` table UPDATE event **Update frequency:** Immediate

---

#### **Circle Messages**

**What changes:** New message sent in a Circle chat **Why it matters:** Secure real-time comms is a core feature — messages must appear instantly **Recommended:** Supabase Realtime subscription on `messages` table INSERT event **Update frequency:** Immediate

---

#### **Device Pending Approvals**

**What changes:** New unknown device discovered on the network **Why it matters:** Pending badge count on the Devices tab must update without refresh **Recommended:** Supabase Realtime subscription on `devices` table INSERT event where `category = 'pending'` **Update frequency:** Immediate

---

#### **Health Score**

**What changes:** Security health score recalculates as alerts are created/resolved **Why it matters:** Dashboard hero ring shows current score — should reflect current state **Recommended:** Polling every 60 seconds OR Supabase Realtime on score recalculation **Update frequency:** Every 60 seconds is acceptable

---

### **Supabase Realtime Implementation Pattern**

The Supabase client is already initialized in the codebase. Here is the pattern to implement subscriptions:

// Example: Subscribe to new alerts  
const subscription \= supabase  
  .channel('alerts-channel')  
  .on(  
    'postgres\_changes',  
    {  
      event: 'INSERT',  
      schema: 'public',  
      table: 'alerts',  
      filter: \`guardian\_id=eq.${guardianId}\`  
    },  
    (payload) \=\> {  
      // New alert received  
      // Add to alerts list in state  
      // Show toast notification  
    }  
  )  
  .subscribe();

// Always unsubscribe on component unmount  
return () \=\> { supabase.removeChannel(subscription); };

---

### **Offline Detection**

The frontend already has an `OfflineBanner` component. Currently `isOffline` is hardcoded to `false`.

**Cyberzeus needs to confirm:** Does "offline" mean the user's internet is down, or the Guardian hardware device is unreachable? The frontend banner says "Guardian offline" — so it specifically refers to the Guardian device being unreachable, not the user's internet.

**Recommended implementation:**

1. Frontend subscribes to Guardian status via Realtime or WebSocket  
2. If no heartbeat received from Guardian in 60 seconds → show offline banner  
3. When Guardian reconnects → hide banner, refresh stale data  
4. Use `navigator.onLine` \+ `online`/`offline` browser events for internet connectivity separately

---

## **4\. ENVIRONMENT VARIABLES NEEDED FROM CYBERZEUS**

The frontend needs these values from Cyberzeus to connect to production:

| Variable | What It Is | Where Used |
| ----- | ----- | ----- |
| Supabase Project ID | The Supabase project reference ID | `/utils/supabase/info.tsx` |
| Supabase Anon Key | Public API key for client-side calls | `/utils/supabase/info.tsx` |
| Edge Function base URL | Full URL to the Hono server function | All API calls |

The backend needs these set as Edge Function secrets:

| Secret | What It Is |
| ----- | ----- |
| `SUPABASE_URL` | Full Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Admin key — never expose to frontend |
| `SUPABASE_ANON_KEY` | Public anon key |

---

*Prepared by Lightning Leap Analytics Pvt. Ltd.* *For Cyberzeus Engineering Team — March 2026*