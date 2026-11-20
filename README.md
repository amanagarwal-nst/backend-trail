# Backend Trail

The 15-day Node.js revision trail, with Google sign-in and an admin dashboard. No passwords anywhere.

- **Students** open `/` and click **Continue with Google**. Their checklist, quiz scores, mock-test best, XP and missed questions save to their account automatically and follow them across devices.
- **Admins** open `/admin` and sign in with Google. Only emails listed in `ADMIN_EMAILS` get in. The dashboard shows every student's days complete, XP, quiz accuracy, mock best, missed questions and last activity, per-day scores, how many students have finished each day, and a CSV export.

## Project layout

```
public/index.html     student app (sign-in screen + the trail)
public/admin.html     admin dashboard
api/google.js         Google sign-in: sends people to Google and handles the callback
api/auth.js           current student, sign-out, sign-in settings
api/progress.js       load / save a student's progress
api/admin.js          student list, student detail, delete
api/_lib/core.js      Redis client, JWT cookie sessions, validation, rate limiting
vercel.json           serves /public as the site, clean URLs (/admin), security headers
```

**How sign-in works:** OAuth 2.0 authorization code flow with PKCE, `state` and `nonce`. The server exchanges the code with Google, verifies the ID token's signature, issuer, audience, expiry and nonce, and only accepts verified emails. It then sets its own session as a signed JWT in an HttpOnly, SameSite=Lax, Secure cookie.

## Deploy to Vercel

### 1. Upload the project
Push this folder to a GitHub repo and import it in Vercel (*Add New → Project*), or run `npx vercel` inside the folder. Framework preset: *Other*. No build step. Note your site address, e.g. `https://backend-trail.vercel.app`.

### 2. Create the Google OAuth client
1. Go to [Google Cloud Console](https://console.cloud.google.com/) and create (or pick) a project.
2. *APIs & Services → OAuth consent screen*: choose **External** (or **Internal** if every student is on your Google Workspace domain), fill in the app name and support email, and add the scopes `openid`, `email`, `profile`. Publish the app so any student can sign in (while in *Testing*, only listed test users can).
3. *APIs & Services → Credentials → Create credentials → OAuth client ID → Web application*.
4. Under **Authorized redirect URIs** add exactly:
   `https://YOUR-SITE.vercel.app/api/google`
   (Add `http://localhost:3000/api/google` too if you will run `vercel dev`.)
5. Copy the **Client ID** and **Client secret**.

### 3. Add a database
In the Vercel project: *Storage → Create Database → Upstash (Redis)*, free plan, connect it to this project. This adds `KV_REST_API_URL` and `KV_REST_API_TOKEN` automatically.

### 4. Set environment variables
*Settings → Environment Variables*:

| Name | Value |
|---|---|
| `GOOGLE_CLIENT_ID` | From step 2 |
| `GOOGLE_CLIENT_SECRET` | From step 2 |
| `JWT_SECRET` | Random, 32+ characters: `openssl rand -base64 48` |
| `ADMIN_EMAILS` | Google accounts allowed into `/admin`, comma-separated |
| `ALLOWED_EMAIL_DOMAINS` | Optional. e.g. `college.edu` so only college Google accounts can join as students |
| `APP_URL` | Optional. Your site address, if you use a custom domain |

### 5. Redeploy
*Deployments → ⋯ → Redeploy*, so the variables take effect. Then open `/` as a student and `/admin` as an admin.

## Run locally

```bash
npm install
npm i -g vercel
vercel link
vercel env pull .env.local
vercel dev     # http://localhost:3000 and http://localhost:3000/admin
```

## Notes

- **Who can join:** without `ALLOWED_EMAIL_DOMAINS`, anyone with a Google account can create a student account. Set it if the site link may spread beyond your class.
- **Adding or removing admins:** edit `ADMIN_EMAILS` and redeploy. Removing an email locks that person out immediately.
- **Deleting a student** removes their progress. If they sign in with Google again, they start fresh from Day 1.
- **Scores are reported by the browser.** Quizzes run in the student's browser, so treat the dashboard as a progress tracker, not a proctored exam.
- **Old progress:** if a student used the earlier no-account version in the same browser, that progress moves into their account the first time they sign in there.
- Changing `JWT_SECRET` signs everyone out.
