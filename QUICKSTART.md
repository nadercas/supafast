# 🚀 Quick Start Guide

Get your Supabase deployer live on Vercel in 5 minutes.

## Prerequisites

- Node.js 18+ installed
- GitHub account
- Vercel account (free tier works)

## Step 1: Clone & Test Locally (2 min)

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Open http://localhost:3000
# Test the interface (you don't need to deploy a real server yet)
```

Verify:
- ✅ Page loads without errors
- ✅ Forms are interactive
- ✅ No console errors in browser DevTools

## Step 2: Push to GitHub (1 min)

```bash
# Initialize git (if not already done)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: Supabase deployer"

# Create a new repo on GitHub, then:
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

## Step 3: Deploy to Vercel (2 min)

### Option A: Vercel Dashboard (Easiest)

1. Go to [vercel.com/new](https://vercel.com/new)
2. Click "Import Git Repository"
3. Select your GitHub repo
4. Click "Deploy" (Vercel auto-detects Next.js, no config needed)
5. Wait ~60 seconds for build
6. Done! 🎉

### Option B: Vercel CLI (Power Users)

```bash
# Install Vercel CLI
npm i -g vercel

# Login
vercel login

# Deploy
vercel

# Deploy to production
vercel --prod
```

## Step 4: Test Your Deployment

1. Visit your Vercel URL: `https://your-project.vercel.app`
2. Test the full flow:
   - Enter a Hetzner API token (get one at [console.hetzner.cloud](https://console.hetzner.cloud) → Security → API Tokens)
   - Fill out the configuration
   - You can deploy a real server or just test the UI

## What's Next?

### Use the Deployer

1. Get a Hetzner Cloud API token (Read & Write)
2. Order a Storage Box at [hetzner.com/storage/storage-box](https://www.hetzner.com/storage/storage-box)
3. Use your deployed app to spin up Supabase servers!

### Customize

- Edit `components/SupabaseDeployer.jsx` to modify the UI
- Update `app/layout.jsx` to change metadata/SEO
- Modify `README.md` with your project details

### Add a Custom Domain (Optional)

1. Go to Vercel project → Settings → Domains
2. Add your domain (e.g., `deploy.yourdomain.com`)
3. Configure DNS as instructed by Vercel
4. Wait for SSL certificate (automatic)

## Troubleshooting

### Build fails on Vercel

Check the build logs. Common issues:
- Node version mismatch (ensure 18+ in Vercel settings)
- Missing dependencies (run `npm install` locally first)

### Page doesn't load

- Clear browser cache
- Check browser console for errors
- Verify deployment completed successfully

### Hetzner API errors

- Ensure API token has Read & Write permissions
- Check token hasn't expired
- Verify Hetzner account is in good standing

## Need Help?

- 📖 Read the full [README.md](README.md)
- 🚀 Check [DEPLOYMENT.md](DEPLOYMENT.md) for advanced options
- ✅ Use [CHECKLIST.md](CHECKLIST.md) before going live
- 🐛 Open an issue on GitHub

---

**That's it!** You now have a zero-knowledge Supabase deployment tool running on Vercel. 🎉

**Security Note:** This tool runs entirely client-side. No secrets ever touch your Vercel deployment — everything happens in the user's browser via direct API calls to Hetzner.
