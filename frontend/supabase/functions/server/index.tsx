import { Hono } from "npm:hono";
import { cors } from "npm:hono/cors";
import { logger } from "npm:hono/logger";
import { createClient } from "npm:@supabase/supabase-js@2";

const app = new Hono();

// Enable logger
app.use("*", logger(console.log));

// Enable CORS for all routes and methods
app.use(
  "/*",
  cors({
    origin: "*",
    allowHeaders: ["Content-Type", "Authorization"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    exposeHeaders: ["Content-Length"],
    maxAge: 600,
  })
);

// Health check endpoint
app.get("/make-server-8c142015/health", (c) => {
  return c.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── AUTH ────────────────────────────────────────────────────────────────────

/**
 * POST /make-server-8c142015/auth/signup
 * Creates a new user account.
 * Uses service role key to bypass email confirmation.
 */
app.post("/make-server-8c142015/auth/signup", async (c) => {
  try {
    const { email, password, name } = await c.req.json();

    if (!email || !password) {
      return c.json({ error: "Email and password are required" }, 400);
    }
    if (password.length < 8) {
      return c.json({ error: "Password must be at least 8 characters" }, 400);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      user_metadata: { name: name || email.split("@")[0] },
      // Automatically confirm the user's email since an email server hasn't been configured.
      email_confirm: true,
    });

    if (error) {
      console.log("Signup error:", error.message);
      return c.json({ error: error.message }, 400);
    }

    return c.json({ user: { id: data.user.id, email: data.user.email } }, 201);
  } catch (err) {
    console.log("Signup exception:", err);
    return c.json({ error: "Internal server error during signup" }, 500);
  }
});

/**
 * GET /make-server-8c142015/auth/profile
 * Returns the authenticated user's profile. Protected route.
 */
app.get("/make-server-8c142015/auth/profile", async (c) => {
  try {
    const accessToken = c.req.header("Authorization")?.split(" ")[1];
    if (!accessToken) {
      return c.json({ error: "No authorization token provided" }, 401);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data: { user }, error } = await supabase.auth.getUser(accessToken);
    if (error || !user) {
      return c.json({ error: "Unauthorized — invalid or expired session" }, 401);
    }

    return c.json({
      id: user.id,
      email: user.email,
      name: user.user_metadata?.name || user.email,
      created_at: user.created_at,
    });
  } catch (err) {
    console.log("Profile error:", err);
    return c.json({ error: "Internal server error fetching profile" }, 500);
  }
});

Deno.serve(app.fetch);
