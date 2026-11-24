import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method tidak didukung." }), {
      status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const { action, code, token } = await req.json();
    const url = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !serviceKey) throw new Error("Konfigurasi server belum lengkap.");

    const db = createClient(url, serviceKey, { auth: { persistSession: false } });

    if (action === "activate") {
      const cleanCode = String(code || "").replace(/[^a-f0-9]/gi, "").toUpperCase();
      if (cleanCode.length !== 16) {
        return new Response(JSON.stringify({ valid: false, error: "Format kode aktivasi tidak valid." }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const codeHash = await sha256(cleanCode);
      const { data: codeRow, error: findError } = await db
        .from("activation_codes").select("id, redeemed_at")
        .eq("code_hash", codeHash).is("redeemed_at", null).maybeSingle();

      if (findError) throw findError;
      if (!codeRow) {
        return new Response(JSON.stringify({ valid: false, error: "Kode tidak ditemukan atau sudah digunakan." }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const licenseToken = [...crypto.getRandomValues(new Uint8Array(32))]
        .map((b) => b.toString(16).padStart(2, "0")).join("");
      const tokenHash = await sha256(licenseToken);

      const { data: claimed, error: claimError } = await db
        .from("activation_codes").update({ redeemed_at: new Date().toISOString() })
        .eq("id", codeRow.id).is("redeemed_at", null).select("id").maybeSingle();

      if (claimError) throw claimError;
      if (!claimed) {
        return new Response(JSON.stringify({ valid: false, error: "Kode sudah digunakan. Hubungi admin jika ini kesalahan." }), {
          status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const { error: insertError } = await db.from("premium_licenses")
        .insert({ activation_code_id: codeRow.id, token_hash: tokenHash });
      if (insertError) throw insertError;

      return new Response(JSON.stringify({ valid: true, token: licenseToken, message: "Premium berhasil diaktifkan." }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (action === "verify") {
      const cleanToken = String(token || "").trim();
      if (cleanToken.length < 32) {
        return new Response(JSON.stringify({ valid: false }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      const tokenHash = await sha256(cleanToken);
      const { data, error } = await db.from("premium_licenses").select("id")
        .eq("token_hash", tokenHash).is("revoked_at", null).maybeSingle();
      if (error) throw error;
      return new Response(JSON.stringify({ valid: !!data }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Aksi tidak dikenal." }), {
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error(err);
    return new Response(JSON.stringify({ error: "Terjadi kesalahan server. Coba lagi atau hubungi admin." }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
