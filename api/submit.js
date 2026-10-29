
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const BLOCKED_DOMAINS = [
  'mailinator.com',
  'tempmail.com',
  'yopmail.com',
  'guerrillamail.com',
  '10minutemail.com',
  'sharklasers.com',
  'throwawaymail.com',
  'getnada.com'
];

const BLOCKED_TLDS = [
  '.xyz', '.icu', '.top', '.tk', '.ml',
  '.ga', '.cf', '.gq', '.ru', '.cn'
];

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  const { honeypot, formData } = req.body || {};

  // Silently ignore bot submissions.
  if (typeof honeypot === 'string' && honeypot.trim()) {
    return res.status(200).json({ success: true });
  }

  if (!formData || typeof formData !== 'object' || Array.isArray(formData)) {
    return res.status(400).json({
      error: 'Invalid form submission.'
    });
  }

  const user_email =
    typeof formData.user_email === 'string'
      ? formData.user_email.trim().toLowerCase()
      : '';

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user_email)) {
    return res.status(400).json({
      error: 'Invalid email address.'
    });
  }

  const emailDomain = user_email.split('@').pop();

  if (
    BLOCKED_DOMAINS.includes(emailDomain) ||
    BLOCKED_TLDS.some(tld => emailDomain.endsWith(tld))
  ) {
    return res.status(400).json({
      error: 'Please use a professional email address.'
    });
  }

  const submission = {
    ...formData,
    user_email
  };

  try {
    const { data: existingUser, error: lookupError } =
      await supabase
        .from('diagnostic_submissions')
        .select('user_email')
        .eq('user_email', user_email)
        .maybeSingle();

    if (lookupError) {
      console.error('Email lookup error:', lookupError);
      return res.status(500).json({
        error: 'Could not verify this email. Please try again.'
      });
    }

    if (existingUser) {
      return res.status(409).json({
        error: 'We’ve already received a submission from this email address.'
      });
    }

    const { error: insertError } = await supabase
      .from('diagnostic_submissions')
      .insert([submission]);

    if (insertError) {
      if (insertError.code === '23505') {
        return res.status(409).json({
          error: 'We’ve already received a submission from this email address.'
        });
      }

      console.error('Supabase insert error:', insertError);
      return res.status(500).json({
        error: 'Could not save your submission. Please try again.'
      });
    }

    return res.status(200).json({ success: true });

  } catch (error) {
    console.error('Submission API error:', error);
    return res.status(500).json({
      error: 'Internal server error.'
    });
  }
}
