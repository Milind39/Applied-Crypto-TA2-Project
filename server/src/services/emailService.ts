import nodemailer from 'nodemailer';
import { config } from '../config';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.email.user,
    pass: config.email.pass,
  },
});

export async function sendVerificationEmail(
  email: string,
  token: string
): Promise<{ success: boolean; error?: string }> {
  const verificationLink = `${config.frontendUrl}/verify-email?token=${token}&email=${encodeURIComponent(email)}`;

  const mailOptions = {
    from: `"PQ Messenger" <${config.email.from}>`,
    to: email,
    subject: 'Verify Your Email — PQ Messenger',
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 580px; margin: 0 auto; background: #0a0a0f; color: #e5e7eb; border: 1px solid #1f2937; border-radius: 12px; padding: 28px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <div style="display: inline-block; background: rgba(0, 255, 65, 0.1); border: 1px solid rgba(0, 255, 65, 0.3); border-radius: 8px; padding: 6px 14px; font-family: monospace; font-size: 16px; font-weight: bold; color: #00ff41;">
            PQ Messenger
          </div>
        </div>
        <h2 style="color: #ffffff; font-size: 20px; font-weight: 600; text-align: center; margin-bottom: 12px;">Verify Your Email Address</h2>
        <p style="font-size: 14px; color: #9ca3af; line-height: 1.6; text-align: center; margin-bottom: 24px;">
          Thank you for registering on PQ Messenger. Please verify your email to activate your account and complete post-quantum cryptographic identity setup.
        </p>
        <div style="text-align: center; margin-bottom: 28px;">
          <a href="${verificationLink}" style="display: inline-block; background: #00ff41; color: #0a0a0f; font-weight: 600; font-size: 14px; text-decoration: none; padding: 12px 28px; border-radius: 8px;">
            Verify Email Address
          </a>
        </div>
        <p style="font-size: 12px; color: #6b7280; line-height: 1.5; text-align: center;">
          Or copy and paste this link in your browser:<br/>
          <a href="${verificationLink}" style="color: #06b6d4; word-break: break-all;">${verificationLink}</a>
        </p>
        <hr style="border: none; border-top: 1px solid #1f2937; margin: 24px 0;" />
        <p style="font-size: 11px; color: #6b7280; text-align: center;">
          This verification link will expire in 24 hours. If you did not create an account, you can safely ignore this email.
        </p>
      </div>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('[EmailService] Verification email sent:', info.messageId);
    return { success: true };
  } catch (error: any) {
    console.error('[EmailService] Error sending email:', error.message);
    return { success: false, error: error.message };
  }
}

export async function sendPasswordResetEmail(
  email: string,
  token: string
): Promise<{ success: boolean; error?: string }> {
  const resetLink = `${config.frontendUrl}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;

  const mailOptions = {
    from: `"PQ Messenger" <${config.email.from}>`,
    to: email,
    subject: 'Reset Your Password — PQ Messenger',
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 580px; margin: 0 auto; background: #0a0a0f; color: #e5e7eb; border: 1px solid #1f2937; border-radius: 12px; padding: 28px;">
        <div style="text-align: center; margin-bottom: 24px;">
          <div style="display: inline-block; background: rgba(0, 255, 65, 0.1); border: 1px solid rgba(0, 255, 65, 0.3); border-radius: 8px; padding: 6px 14px; font-family: monospace; font-size: 16px; font-weight: bold; color: #00ff41;">
            PQ Messenger
          </div>
        </div>
        <h2 style="color: #ffffff; font-size: 20px; font-weight: 600; text-align: center; margin-bottom: 12px;">Reset Your Password</h2>
        <p style="font-size: 14px; color: #9ca3af; line-height: 1.6; text-align: center; margin-bottom: 20px;">
          We received a request to reset your password for your PQ Messenger account.
        </p>
        <div style="background: #111827; border: 1px solid #374151; border-radius: 8px; padding: 16px; text-align: center; margin-bottom: 24px;">
          <p style="font-size: 12px; color: #9ca3af; margin: 0 0 8px 0; text-transform: uppercase; letter-spacing: 1px;">Your Reset Token</p>
          <div style="font-family: monospace; font-size: 16px; font-weight: bold; color: #00ff41; letter-spacing: 1px; word-break: break-all;">
            ${token}
          </div>
        </div>
        <div style="text-align: center; margin-bottom: 24px;">
          <a href="${resetLink}" style="display: inline-block; background: #00ff41; color: #0a0a0f; font-weight: 600; font-size: 14px; text-decoration: none; padding: 12px 28px; border-radius: 8px;">
            Reset Password Directly
          </a>
        </div>
        <p style="font-size: 12px; color: #6b7280; line-height: 1.5; text-align: center;">
          Or copy and paste this link in your browser:<br/>
          <a href="${resetLink}" style="color: #06b6d4; word-break: break-all;">${resetLink}</a>
        </p>
        <hr style="border: none; border-top: 1px solid #1f2937; margin: 24px 0;" />
        <p style="font-size: 11px; color: #6b7280; text-align: center;">
          This password reset token will expire in 15 minutes. If you did not request a password reset, you can safely ignore this email.
        </p>
      </div>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('[EmailService] Password reset email sent:', info.messageId);
    return { success: true };
  } catch (error: any) {
    console.error('[EmailService] Error sending password reset email:', error.message);
    return { success: false, error: error.message };
  }
}
