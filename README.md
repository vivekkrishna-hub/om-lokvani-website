# Om Lokvani — Complete Production Website

This package contains the colorful, responsive, multi-page Om Lokvani website and the production-oriented backend.

## Pages
- `/` Home
- `/about` About Us
- `/services` Services
- `/apply` Apply Online
- `/track` Track Application
- `/inquiry` Inquiry
- `/fees` Service Fee
- `/contact` Contact Us
- `/admin` Admin Login + Dashboard

## Backend features
- Supabase PostgreSQL for applications, inquiries, services, admin users and audit logs
- Private Supabase Storage bucket `private-documents`
- Customer document uploads (JPG/PNG/PDF, server-side limits)
- Application tracking
- Dynamic service fees
- 3-mobile admin login + MSG91 OTP
- bcrypt password storage and JWT admin sessions
- Password change
- Razorpay order creation
- Server-side Razorpay signature and payment verification
- Razorpay webhook signature verification and idempotent webhook events
- Admin-only signed document URLs
- Security headers and rate limiting
- Print / Download application receipt

## Required production configuration
Copy `.env.example` to your hosting environment variables and replace placeholders with real credentials. Never put server secrets in HTML or client-side JavaScript.

Run `supabase/schema.sql` in the Supabase SQL Editor before using the backend.

For Render, use:
- Build command: `npm install`
- Start command: `npm start`
- Add all variables from `.env.example` in Render Environment.

Razorpay webhook URL:
`https://YOUR-DOMAIN.example/api/webhooks/razorpay`

Use Test Mode first. Switch to Live keys only after the complete test flow passes.
