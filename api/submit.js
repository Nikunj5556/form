import { createClient } from '@supabase/supabase-js';

// Initialize Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Blocked Disposable Domains & Suspicious TLDs
const BLOCKED_DOMAINS = [
  'mailinator.com', 'tempmail.com', 'yopmail.com', 'guerrillamail.com',
  '10minutemail.com', 'sharklasers.com', 'throwawaymail.com', 'getnada.com'
];
const BLOCKED_TLDS = ['.xyz', '.icu', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn'];

export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { captchaToken, honeypot, formData } = req.body;
  const user_email = formData?.user_email;

  try {
    // 1. Honeypot Protection (Silent Success)
    if (honeypot && honeypot.length > 0) {
      console.warn('Bot detected via honeypot'); 
      // Return success to fool the bot, do NOT insert into DB
      return res.status(200).json({ success: true });
    }

    // 2. Hardened Email Validation
    if (!user_email || !user_email.includes('@')) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }

    // 3. Disposable Email Detection
    const emailDomain = user_email.split('@')[1].toLowerCase();
    const isDisposable = BLOCKED_DOMAINS.includes(emailDomain);
    const isSuspiciousTLD = BLOCKED_TLDS.some(tld => emailDomain.endsWith(tld));

    if (isDisposable || isSuspiciousTLD) {
      return res.status(400).json({
        error: 'Please use a professional email address.'
      });
    }

    // 4. Invisible reCAPTCHA Verification (Server-Side)
    const recaptchaSecret = process.env.RECAPTCHA_SECRET_KEY;
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${recaptchaSecret}&response=${captchaToken}`;

    const captchaResponse = await fetch(verifyUrl, { method: 'POST' });
    const captchaData = await captchaResponse.json();

    // Verify Success, Score, AND Action
    if (!captchaData.success || captchaData.score < 0.5 || captchaData.action !== 'submit') {
      console.warn(`Security verification failed. Score: ${captchaData.score}, Action: ${captchaData.action}`);
      return res.status(403).json({ error: 'Security verification failed. Please try again.' });
    }

    // 5. Email Uniqueness (Soft Check)
    // Using .maybeSingle() to avoid 500 error if not found
    const { data: existingUser } = await supabase
      .from('diagnostic_submissions')
      .select('user_email')
      .eq('user_email', user_email)
      .maybeSingle();

    if (existingUser) {
      return res.status(409).json({
        error: "We’ve already received a submission from this email address."
      });
    }

    // 6. Insert Data (Database is final authority)
    const { error: insertError } = await supabase
      .from('diagnostic_submissions')
      .insert([formData]);

    // Handle SQL Unique Constraint Violation (Race conditions)
    if (insertError) {
      if (insertError.code === '23505') { // Postgres unique_violation code
        return res.status(409).json({
          error: "We’ve already received a submission from this email address."
        });
      }
      
      console.error('Supabase Insert Error:', insertError);
      throw new Error('Database error');
    }

    return res.status(200).json({ success: true });

  } catch (err) {
    console.error('API Error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
