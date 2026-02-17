# Pre-Deployment Checklist

## Before Pushing to Vercel

- [ ] Test locally (`npm run dev`)
- [ ] Build succeeds (`npm run build`)
- [ ] No console errors in browser
- [ ] Test full deployment flow with Hetzner sandbox/test server
- [ ] Verify SSH key generation works
- [ ] Verify cloud-init script syntax (no JS interpolation bugs)
- [ ] Check all form validations work
- [ ] Test credential copy functionality
- [ ] Verify zero-knowledge architecture (check Network tab — only api.hetzner.cloud calls)

## Git Setup

```bash
# Initialize repo if not already done
git init

# Create .gitignore (already done)

# Add all files
git add .

# Commit
git commit -m "Initial commit: Supabase zero-knowledge deployer"

# Add remote
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git

# Push
git push -u origin main
```

## Vercel Deployment

### First Time Setup

1. [ ] Create GitHub repository
2. [ ] Push code to GitHub
3. [ ] Go to [vercel.com](https://vercel.com)
4. [ ] Import GitHub repository
5. [ ] Configure project:
   - Framework: Next.js (auto-detected)
   - Build command: `npm run build`
   - Output directory: `.next`
   - Install command: `npm install`
6. [ ] Deploy
7. [ ] Test deployed app thoroughly

### Subsequent Deployments

```bash
# Automatic deployment via Git
git add .
git commit -m "Your changes"
git push

# Or use Vercel CLI
vercel --prod
```

## Post-Deployment Verification

- [ ] Visit deployed URL
- [ ] Test API token validation
- [ ] Generate SSH keypair (check browser console for errors)
- [ ] Fill out configuration form
- [ ] Review step shows all correct values
- [ ] Deploy a test server to Hetzner
- [ ] Monitor deployment progress (labels update correctly)
- [ ] Verify completion page shows all credentials
- [ ] Copy credentials works
- [ ] SSH private key displays correctly
- [ ] Test SSH access: `ssh -i ~/.ssh/keyfile deploy-user@server-ip`
- [ ] Access Supabase Studio at domain
- [ ] Verify backup ran: SSH in and check `/var/log/supabase-backup-server-name.log`

## Security Verification

- [ ] No secrets logged to browser console
- [ ] No secrets sent to any server other than api.hetzner.cloud
- [ ] Check Network tab: only Hetzner API calls present
- [ ] Verify security headers in response (X-Frame-Options, etc.)
- [ ] SSH private key only shown on completion page
- [ ] Test that closing browser clears all secrets from memory

## Common Issues

### Build Fails
```bash
# Check Node version (should be 18+)
node --version

# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install

# Try build again
npm run build
```

### Runtime Errors
- Check browser console
- Verify Next.js app router is properly configured
- Ensure all imports use correct paths

### API Errors
- Verify Hetzner API token has Read & Write permissions
- Check CORS headers in Network tab
- Ensure api.hetzner.cloud is accessible

## Optional: Custom Domain

1. [ ] Purchase domain
2. [ ] Configure DNS:
   - Add CNAME record: `@` → `cname.vercel-dns.com`
   - Or A records to Vercel IPs (check Vercel docs)
3. [ ] Add domain in Vercel project settings
4. [ ] Wait for SSL certificate provisioning
5. [ ] Test HTTPS access

## Monitoring

- [ ] Set up Vercel Analytics (optional)
- [ ] Monitor deployment frequency
- [ ] Check build times
- [ ] Review error logs if any

## Maintenance

### Regular Updates
```bash
# Update dependencies
npm update

# Check for major updates
npm outdated

# Update Next.js
npm install next@latest react@latest react-dom@latest

# Test after updates
npm run dev
npm run build
```

### Security Updates
- [ ] Enable Dependabot alerts on GitHub
- [ ] Review and merge security PRs
- [ ] Test after security updates

## Documentation

- [ ] README.md is up to date
- [ ] DEPLOYMENT.md has correct instructions
- [ ] Add screenshots/demo GIF (optional)
- [ ] Update GitHub repository description
- [ ] Add topics/tags to GitHub repo

## Marketing (Optional)

- [ ] Share on Twitter/X
- [ ] Post to r/selfhosted
- [ ] Submit to Hacker News
- [ ] Add to awesome-supabase lists
- [ ] Write blog post about the project

## Final Checklist

- [ ] All features work as expected
- [ ] Code is clean and commented
- [ ] No console errors or warnings
- [ ] Mobile responsive (test on phone)
- [ ] Fast load time (< 2s)
- [ ] Accessible (keyboard navigation works)
- [ ] SEO meta tags configured
- [ ] Open Graph tags set
- [ ] License file added
- [ ] Contributing guidelines (optional)

## Success Criteria

✅ User can deploy Supabase without leaving the browser
✅ SSH keys generated client-side
✅ No backend required
✅ All secrets stay in browser memory
✅ Cloud-init automation works end-to-end
✅ Backups configured automatically
✅ Server hardening applied
✅ Zero manual SSH intervention needed

---

**Ready to deploy?** Run through this checklist and you're good to go! 🚀
