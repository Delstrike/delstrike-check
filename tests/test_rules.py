"""Per rule: at least two positive and two negative fixtures. A negative is the correct pattern that must not fire."""
from __future__ import annotations

from conftest import FIREBASE_PKG, fake_jwt, fake_key, ids, run

# ---------------------------------------------------------------- SB-EDGE-NOAUTH

EDGE_NOAUTH = """import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async (req) => {
  const { id, status } = await req.json();
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  await admin.from("jobs").update({ status }).eq("id", id);
  return new Response("ok");
});
"""
EDGE_AUTH = """import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async (req) => {
  const userClient = createClient(URL, ANON, { global: { headers: { Authorization: req.headers.get("Authorization")! } } });
  const { data: { user } } = await userClient.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const admin = createClient(URL, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  return new Response("ok");
});
"""


def test_noauth_edge_function(project):
    r = run(project({"supabase/functions/callback/index.ts": EDGE_NOAUTH}))
    [f] = ids(r, "SB-EDGE-NOAUTH")
    assert (f.severity, f.confidence, f.file, f.lines) == ("high", "high", "supabase/functions/callback/index.ts", [4])


def test_noauth_next_api_route(project):
    code = EDGE_NOAUTH.replace("Deno.serve(async (req) =>", "export async function POST(req: Request)").replace(
        'Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!', "process.env.SUPABASE_SERVICE_ROLE_KEY!").replace("});\n", "}\n")
    r = run(project({"app/api/jobs/route.ts": code}))
    assert [f.file for f in ids(r, "SB-EDGE-NOAUTH")] == ["app/api/jobs/route.ts"]


def test_noauth_negative_get_user(project):
    r = run(project({"supabase/functions/ok/index.ts": EDGE_AUTH}))
    assert not ids(r, "SB-EDGE-NOAUTH")


def test_noauth_negative_shared_secret_and_helper(project):
    secret = EDGE_NOAUTH.replace("const { id", 'if (req.headers.get("x-webhook-secret") !== Deno.env.get("HOOK")) '
                                               'return new Response("no", { status: 401 });\n  const { id')
    helper = ("import { requireUser } from '../_shared/auth.ts';\n" + EDGE_NOAUTH.replace(
        "const { id", "const user = await requireUser(req);\n  const { id"))
    shared = "export async function requireUser(req: Request) {\n  const { data } = await client.auth.getUser();\n" \
             "  return data.user;\n}\n"
    r = run(project({"supabase/functions/a/index.ts": secret, "supabase/functions/b/index.ts": helper,
                     "supabase/functions/_shared/auth.ts": shared}))
    assert not ids(r, "SB-EDGE-NOAUTH")


def test_noauth_helper_imported_but_not_the_auth_one(project):
    shared = ("export function admin() { return createClient(URL, KEY); }\n"
              "export async function requireUser(req) { return (await c.auth.getUser()).data.user; }\n")
    code = "import { admin } from '../_shared/clients.ts';\n" + EDGE_NOAUTH
    r = run(project({"supabase/functions/a/index.ts": code, "supabase/functions/_shared/clients.ts": shared}))
    assert len(ids(r, "SB-EDGE-NOAUTH")) == 1


# ---------------------------------------------------------------- SB-EDGE-JWT-OFF

CONFIG = """[api]
enabled = true

[functions.callback]
verify_jwt = false

[functions.stripe-webhook]
verify_jwt = false

[functions.public-ok]
verify_jwt = true
"""
STRIPE = "import Stripe from 'npm:stripe';\nDeno.serve(async (req) => {\n  const e = await stripe.webhooks." \
         "constructEventAsync(body, sig, secret);\n  const db = createClient(U, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'));\n});\n"


def test_jwt_off_escalates_with_noauth(project):
    r = run(project({"supabase/config.toml": CONFIG, "supabase/functions/callback/index.ts": EDGE_NOAUTH}))
    f = next(f for f in ids(r, "SB-EDGE-JWT-OFF") if "callback" in f.message and "stripe" not in f.message)
    assert (f.severity, f.lines) == ("high", [5])


def test_jwt_off_medium_without_service_key(project):
    r = run(project({"supabase/config.toml": "[functions.hello]\nverify_jwt = false\n",
                     "supabase/functions/hello/index.ts": "Deno.serve(() => new Response('hi'));\n"}))
    [f] = ids(r, "SB-EDGE-JWT-OFF")
    assert f.severity == "medium"


def test_jwt_off_negative_webhook_is_info_and_hidden_by_default(project):
    root = project({"supabase/config.toml": "[functions.stripe-webhook]\nverify_jwt = false\n",
                    "supabase/functions/stripe-webhook/index.ts": STRIPE})
    assert [f.severity for f in ids(run(root), "SB-EDGE-JWT-OFF")] == ["info"]
    assert not ids(run(root, include_all=False), "SB-EDGE-JWT-OFF")


def test_jwt_off_negative_verify_true(project):
    r = run(project({"supabase/config.toml": "[functions.x]\nverify_jwt = true\n"}))
    assert not ids(r, "SB-EDGE-JWT-OFF")


# ---------------------------------------------------------------- SB-SERVICE-ROLE-KEY

def test_service_role_jwt_in_client_code(project):
    r = run(project({"src/lib/supabase.ts": f'export const supabase = createClient(URL, "{fake_jwt("service_role")}");\n'}))
    [f] = ids(r, "SB-SERVICE-ROLE-KEY")
    assert (f.severity, f.file) == ("critical", "src/lib/supabase.ts")
    assert fake_jwt("service_role") not in f.message + f.snippet


def test_service_role_in_public_env_var_even_if_gitignored(project):
    root = project({".gitignore": ".env*\n", ".env.local": f"VITE_SUPABASE_SERVICE_ROLE_KEY={fake_jwt('service_role')}\n"})
    [f] = ids(run(root), "SB-SERVICE-ROLE-KEY")
    assert f.file == ".env.local"


def test_service_role_public_name_in_code_and_sb_secret(project):
    r = run(project({"src/a.ts": "const k = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;\n",
                     "src/b.ts": f'const s = "{fake_key("sb_secret")}";\n'}))
    assert sorted(f.file for f in ids(r, "SB-SERVICE-ROLE-KEY")) == ["src/a.ts", "src/b.ts"]


def test_service_role_negative_anon_key_and_server_env(project):
    root = project({"src/lib/supabase.ts": f'createClient(URL, "{fake_jwt("anon")}");\n',
                    ".gitignore": ".env\n", ".env": f"SUPABASE_SERVICE_ROLE_KEY={fake_jwt('service_role')}\n"})
    assert not ids(run(root), "SB-SERVICE-ROLE-KEY")


def test_service_role_negative_local_demo_key(project):
    r = run(project({"supabase/seed.ts": f'const k = "{fake_jwt("service_role", iss="supabase-demo")}";\n'}))
    assert not ids(r, "SB-SERVICE-ROLE-KEY")


# ---------------------------------------------------------------- SB-POLICY-OPEN

def test_policy_open_anon_write(project):
    sql = "create table public.notes (id uuid, user_id uuid);\nalter table public.notes enable row level security;\n" \
          'create policy "anyone" on public.notes for all using (true) with check (true);\n'
    [f] = ids(run(project({"supabase/migrations/1_init.sql": sql})), "SB-POLICY-OPEN")
    assert (f.severity, f.confidence, f.lines) == ("high", "high", [3])


def test_policy_open_session_write_is_medium_confidence(project):
    sql = "create table posts (id int);\nalter table posts enable row level security;\n" \
          'create policy p on posts for update to authenticated using (auth.uid() is not null);\n'
    [f] = ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OPEN")
    assert (f.severity, f.confidence) == ("high", "medium")


def test_policy_open_global_read_is_grouped(project):
    sql = "".join(f"create table t{i} (id int);\nalter table t{i} enable row level security;\n"
                  f"create policy r{i} on t{i} for select to authenticated using (true);\n" for i in range(4))
    [f] = ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OPEN")
    assert f.extra["tables"] == ["t0", "t1", "t2", "t3"] and f.confidence == "medium"


def test_policy_open_negative_owner_policy(project):
    sql = "create table notes (id int, user_id uuid);\nalter table notes enable row level security;\n" \
          'create policy own on notes for all to authenticated using ((select auth.uid()) = user_id);\n'
    assert not ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OPEN")


def test_policy_open_negative_dropped_later(project):
    r = run(project({
        "supabase/migrations/1.sql": "create table n (id int);\nalter table n enable row level security;\n"
                                     'create policy "open" on n using (true);\n',
        "supabase/migrations/2.sql": 'drop policy if exists "open" on public.n;\n'
                                     "create policy own on n using (auth.uid() = owner);\n"}))
    assert not ids(r, "SB-POLICY-OPEN")


# ---------------------------------------------------------------- SB-RLS-OFF

def test_rls_off_never_enabled(project):
    [f] = ids(run(project({"supabase/migrations/1.sql": "create table public.orders (id int);\n"})), "SB-RLS-OFF")
    assert (f.severity, f.lines) == ("critical", [1])


def test_rls_off_disabled_later(project):
    r = run(project({"supabase/migrations/1.sql": "create table a (id int);\nalter table a enable row level security;\n",
                     "supabase/migrations/2.sql": "\n\nalter table public.a disable row level security;\n"}))
    [f] = ids(r, "SB-RLS-OFF")
    assert (f.file, f.lines) == ("supabase/migrations/2.sql", [3])


def test_rls_off_negative_enabled_and_other_schema(project):
    sql = 'CREATE TABLE "public"."a" (id int);\nALTER TABLE ONLY "public"."a" ENABLE ROW LEVEL SECURITY;\n' \
          "create table private.secrets (id int);\n"
    assert not ids(run(project({"supabase/schema.sql": sql})), "SB-RLS-OFF")


def test_rls_off_negative_without_supabase(project):
    r = run(project({"prisma/migrations/1/migration.sql": "create table users (id int);\n"}, supabase=False))
    assert not ids(r, "SB-RLS-OFF")


def test_rls_off_negative_dropped_table(project):
    r = run(project({"supabase/migrations/1.sql": "create table tmp (id int);\n",
                     "supabase/migrations/2.sql": "drop table if exists public.tmp;\n"}))
    assert not ids(r, "SB-RLS-OFF")


# ---------------------------------------------------------------- SB-POLICY-OVERLAP

def test_overlap_open_and_owner(project):
    sql = "create table c (id int, user_id uuid);\nalter table c enable row level security;\n" \
          'create policy "own" on c for all using (auth.uid() = user_id);\n' \
          'create policy "Enable read access for all users" on c for select using (true);\n'
    [f] = ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OVERLAP")
    assert f.severity == "high" and f.extra["drop"] == 'drop policy "Enable read access for all users" on public.c;'
    assert not ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OPEN")


def test_overlap_session_read_is_medium(project):
    sql = "create table c (id int);\nalter table c enable row level security;\n" \
          "create policy own on c for select using (auth.uid() = user_id);\n" \
          "create policy any on c for select to authenticated using (true);\n"
    [f] = ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OVERLAP")
    assert f.severity == "medium"


def test_overlap_negative_restrictive(project):
    sql = "create table c (id int);\nalter table c enable row level security;\n" \
          "create policy own on c for select using (auth.uid() = user_id);\n" \
          "create policy pub on c as restrictive for select using (true);\n"
    assert not ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OVERLAP")


def test_overlap_negative_different_command(project):
    sql = "create table c (id int);\nalter table c enable row level security;\n" \
          "create policy own on c for update using (auth.uid() = user_id);\n" \
          "create policy pub on c for select to anon using (true);\n"
    assert not ids(run(project({"supabase/migrations/1.sql": sql})), "SB-POLICY-OVERLAP")


# ---------------------------------------------------------------- SB-RPC-DEFINER

DEFINER = """create or replace function public.admin_stats()
returns json language plpgsql security definer as $$
begin
  return (select json_agg(u) from auth.users u);
end;
$$;
"""


def test_rpc_definer(project):
    [f] = ids(run(project({"supabase/migrations/1.sql": DEFINER})), "SB-RPC-DEFINER")
    assert (f.severity, f.confidence, f.lines) == ("medium", "medium", [1])


def test_rpc_definer_nested_dollar_quotes(project):
    sql = DEFINER.replace("as $$", "as $fn$").replace("$$;", "$fn$;").replace(
        "begin", "begin\n  execute $q$select 1$q$;")
    assert ids(run(project({"supabase/migrations/1.sql": sql})), "SB-RPC-DEFINER")


def test_rpc_definer_negative_revoked_or_checks_user(project):
    revoked = DEFINER + "revoke execute on function public.admin_stats() from anon, public;\n"
    checks = DEFINER.replace("begin", "begin\n  if auth.uid() is null then raise exception 'no'; end if;")
    assert not ids(run(project({"supabase/migrations/1.sql": revoked})), "SB-RPC-DEFINER")
    assert not ids(run(project({"supabase/migrations/1.sql": checks})), "SB-RPC-DEFINER")


def test_rpc_definer_negative_trigger(project):
    sql = DEFINER.replace("returns json", "returns trigger")
    assert not ids(run(project({"supabase/migrations/1.sql": sql})), "SB-RPC-DEFINER")


# ---------------------------------------------------------------- AI-PROXY-OPEN

AI = """import OpenAI from "openai";
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
export async function POST(req: Request) {
  const { messages } = await req.json();
  const r = await openai.chat.completions.create({ model: "gpt-4o", messages });
  return Response.json(r);
}
"""


def test_ai_proxy_next_route(project):
    [f] = ids(run(project({"app/api/chat/route.ts": AI})), "AI-PROXY-OPEN")
    assert (f.severity, f.confidence, f.lines) == ("high", "high", [2])
    assert "no request limit" in f.message


def test_ai_proxy_edge_fetch_with_rate_limit_message(project):
    code = "Deno.serve(async (req) => {\n  const { prompt } = await req.json();\n  if (await rateLimit(ip)) " \
           "return new Response('', {status: 429});\n  await fetch('https://api.openai.com/v1/chat/completions', " \
           "{ body: JSON.stringify({ prompt }) });\n});\n"
    [f] = ids(run(project({"supabase/functions/ask/index.ts": code})), "AI-PROXY-OPEN")
    assert "per user" in f.message


def test_ai_proxy_negative_auth(project):
    code = AI.replace("const { messages }", "const session = await getServerSession();\n  if (!session) return;\n"
                                            "  const { messages }")
    assert not ids(run(project({"app/api/chat/route.ts": code})), "AI-PROXY-OPEN")


def test_ai_proxy_negative_server_prompt_only(project):
    code = AI.replace("const { messages } = await req.json();", "const messages = [{ role: 'user', content: 'Hi' }];")
    assert not ids(run(project({"app/api/chat/route.ts": code})), "AI-PROXY-OPEN")


# ---------------------------------------------------------------- FB-RULES-OPEN

def test_fb_rules_true_and_no_condition(project):
    rules = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n" \
            "    match /{doc=**} {\n      allow read, write: if true;\n    }\n    match /logs/{id} { allow create; }\n  }\n}\n"
    found = ids(run(project({"firestore.rules": rules, "package.json": FIREBASE_PKG}, supabase=False)), "FB-RULES-OPEN")
    assert sorted((f.severity, f.lines[0]) for f in found) == [("critical", 5), ("critical", 7)]


def test_fb_rules_test_mode_signed_in_and_rtdb(project):
    rules = "service firebase.storage {\n  match /b/{bucket}/o {\n    match /{all=**} {\n" \
            "      allow read: if request.time < timestamp.date(2026, 12, 1);\n" \
            "      allow write: if request.auth != null;\n    }\n  }\n}\n"
    rtdb = '{\n  "rules": {\n    ".read": true,\n    ".write": "auth != null"\n  }\n}\n'
    found = ids(run(project({"storage.rules": rules, "database.rules.json": rtdb}, supabase=False)), "FB-RULES-OPEN")
    assert sorted((f.file, f.severity) for f in found) == [
        ("database.rules.json", "critical"), ("database.rules.json", "high"),
        ("storage.rules", "critical"), ("storage.rules", "high")]


def test_fb_rules_negative_ownership(project):
    rules = "service cloud.firestore {\n  match /databases/{db}/documents {\n    match /users/{uid} {\n" \
            "      allow read, write: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}\n"
    assert not ids(run(project({"firestore.rules": rules}, supabase=False)), "FB-RULES-OPEN")


def test_fb_rules_negative_comment_and_false(project):
    rules = "service cloud.firestore {\n  // allow read, write: if true;\n  match /x/{id} { allow read: if false; }\n}\n"
    assert not ids(run(project({"firestore.rules": rules}, supabase=False)), "FB-RULES-OPEN")


# ---------------------------------------------------------------- SB-BUCKET-PUBLIC

def test_bucket_public_user_content(project):
    sql = "insert into storage.buckets (id, name, public) values ('documents', 'documents', true);\n"
    [f] = ids(run(project({"supabase/migrations/1.sql": sql})), "SB-BUCKET-PUBLIC")
    assert (f.severity, f.confidence) == ("medium", "medium")


def test_bucket_public_from_config_toml(project):
    toml = "[storage.buckets.invoices]\npublic = true\nfile_size_limit = \"50MiB\"\n"
    [f] = ids(run(project({"supabase/config.toml": toml})), "SB-BUCKET-PUBLIC")
    assert (f.file, f.lines) == ("supabase/config.toml", [2])


def test_bucket_negative_private_or_made_private(project):
    sql = "insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);\n" \
          "insert into storage.buckets (id, name, public) values ('receipts', 'receipts', true);\n" \
          "update storage.buckets set public = false where id = 'receipts';\n"
    assert not ids(run(project({"supabase/migrations/1.sql": sql})), "SB-BUCKET-PUBLIC")


def test_bucket_negative_marketing_assets_hidden_by_default(project):
    sql = "insert into storage.buckets (id, name, public) values ('logos', 'logos', true);\n"
    root = project({"supabase/migrations/1.sql": sql})
    assert [f.severity for f in ids(run(root), "SB-BUCKET-PUBLIC")] == ["low"]
    assert not ids(run(root, include_all=False), "SB-BUCKET-PUBLIC")


# ---------------------------------------------------------------- SB-NO-SCHEMA

def test_no_schema(project):
    [f] = ids(run(project({"src/main.ts": "createClient(url, key)\n"})), "SB-NO-SCHEMA")
    assert (f.severity, f.file, f.lines) == ("info", "package.json", [4])


def test_no_schema_python(project):
    r = run(project({"requirements.txt": "supabase==2.10.0\n"}, supabase=False))
    assert ids(r, "SB-NO-SCHEMA")


def test_no_schema_negative_with_migrations(project):
    sql = "create table a (id int);\nalter table a enable row level security;\n"
    assert not ids(run(project({"supabase/migrations/1.sql": sql})), "SB-NO-SCHEMA")


def test_no_schema_negative_not_supabase(project):
    assert not ids(run(project({"src/x.ts": "export {}\n"}, supabase=False)), "SB-NO-SCHEMA")
    pyproject = '[project]\nname = "x"\nkeywords = ["supabase", "firebase"]\ndependencies = ["httpx>=0.27"]\n'
    assert not ids(run(project({"pyproject.toml": pyproject}, supabase=False)), "SB-NO-SCHEMA")


# ---------------------------------------------------------------- AUTH-CONFIG (FB-AUTH-ANON)

def test_auth_supabase_anonymous_unused(project):
    toml = "[auth]\nenable_signup = true\nenable_anonymous_sign_ins = true\n"
    [f] = ids(run(project({"supabase/config.toml": toml})), "AUTH-CONFIG")
    assert (f.severity, f.confidence, f.lines) == ("low", "high", [3])


def test_auth_firebase_anonymous_and_confirmations_off(project):
    root = project({"firebase.json": '{\n  "auth": {\n    "providers": {\n      "anonymous": true\n    }\n  }\n}\n',
                    "supabase/config.toml": "[auth]\nenable_signup = true\n[auth.email]\nenable_confirmations = false\n"})
    found = ids(run(root), "AUTH-CONFIG")
    assert sorted((f.file, f.confidence) for f in found) == [("firebase.json", "high"), ("supabase/config.toml", "medium")]


def test_auth_negative_used_is_info(project):
    root = project({"supabase/config.toml": "[auth]\nenable_anonymous_sign_ins = true\n",
                    "src/a.ts": "await supabase.auth.signInAnonymously();\n"})
    assert [f.severity for f in ids(run(root), "AUTH-CONFIG")] == ["info"]


def test_auth_negative_defaults(project):
    toml = "[auth]\nenable_signup = false\nenable_anonymous_sign_ins = false\n[auth.email]\nenable_confirmations = false\n"
    assert not ids(run(project({"supabase/config.toml": toml})), "AUTH-CONFIG")


# ---------------------------------------------------------------- ENV-COMMITTED

def test_env_committed_with_secret(project):
    env = f"VITE_SUPABASE_URL=https://abc.supabase.co\nSTRIPE_SECRET_KEY={fake_key('stripe')}\n" \
          "DATABASE_URL=postgres://user:hunter22@db:5432/app\n"
    root = project({".env": env}, tracked=["package.json", ".env"])
    [f] = ids(run(root), "ENV-COMMITTED")
    assert (f.severity, f.lines) == ("critical", [2, 3])
    assert "STRIPE_SECRET_KEY" in f.message and fake_key("stripe") not in f.message


def test_env_not_ignored_without_git(project):
    [f] = ids(run(project({".env.production": f"OPENAI_API_KEY={fake_key('openai')}\n"})), "ENV-COMMITTED")
    assert "isn't covered by .gitignore" in f.message


def test_env_committed_only_publishable_is_info(project):
    env = f"NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY={fake_jwt('anon')}\n"
    [f] = ids(run(project({".env": env}, tracked=[".env"])), "ENV-COMMITTED")
    assert f.severity == "info"


def test_env_negative_gitignored_and_example(project):
    root = project({".gitignore": ".env\n.env.*\n!.env.example\n", ".env": f"STRIPE_SECRET_KEY={fake_key('stripe')}\n",
                    ".env.local": "OPENAI_API_KEY=x\n", ".env.example": "STRIPE_SECRET_KEY=\n"})
    assert not ids(run(root), "ENV-COMMITTED")


def test_env_negative_untracked_in_git_repo(project):
    root = project({".gitignore": ".env\n", ".env": f"STRIPE_SECRET_KEY={fake_key('stripe')}\n"},
                   tracked=["package.json", ".gitignore"])
    assert not ids(run(root), "ENV-COMMITTED")


# ---------------------------------------------------------------- SECRET-KNOWN

def test_secret_known_providers(project):
    code = f'const stripe = new Stripe("{fake_key("stripe")}");\nconst o = "{fake_key("openai")}";\n' \
           f'const a = "{fake_key("anthropic")}";\n'
    found = ids(run(project({"src/pay.ts": code})), "SECRET-KNOWN")
    assert sorted(f.message.split(" secret")[0] for f in found) == ["A Anthropic", "A OpenAI", "A Stripe"]
    assert all(fake_key(k) not in f.message + f.snippet for f in found for k in ("stripe", "openai", "anthropic"))


def test_secret_known_aws_github_and_public_env(project):
    root = project({"deploy.sh": f"export AWS_ACCESS_KEY_ID={fake_key('aws')}\ngh auth {fake_key('github')}\n",
                    ".gitignore": ".env.local\n", ".env.local": f"NEXT_PUBLIC_OPENAI_KEY={fake_key('openai')}\n"})
    found = ids(run(root), "SECRET-KNOWN")
    assert sorted((f.file, f.lines[0]) for f in found) == [(".env.local", 1), ("deploy.sh", 1), ("deploy.sh", 2)]


def test_secret_known_negative_placeholders_tests_examples(project):
    root = project({"src/a.ts": 'const k = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";\n'
                                'const aws = "AKIAIOSFODNN7EXAMPLE";\n',
                    "tests/stripe.test.ts": f'const k = "{fake_key("stripe")}";\n',
                    "docs/config.example.ts": f'const k = "{fake_key("openai")}";\n'})
    assert not ids(run(root), "SECRET-KNOWN")


def test_secret_known_negative_server_env_gitignored(project):
    root = project({".gitignore": ".env\n", ".env": f"OPENAI_API_KEY={fake_key('openai')}\n",
                    "src/a.ts": "const k = process.env.OPENAI_API_KEY;\n"})
    assert not ids(run(root), "SECRET-KNOWN")
