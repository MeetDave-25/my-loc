// Sends email via SMTP when configured; otherwise logs the message so the app
// still works in development. Set SMTP_HOST/PORT/USER/PASS and MAIL_FROM to go live.
import nodemailer from "nodemailer";

let transport = null;
if (process.env.SMTP_HOST) {
  transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
}

export async function sendMail({ to, subject, text }) {
  if (!transport) {
    console.log(`\n[mailer:dev] no SMTP configured — would send to ${to}\n  subject: ${subject}\n  ${text}\n`);
    return { dev: true };
  }
  await transport.sendMail({ from: process.env.MAIL_FROM || "no-reply@whereabouts.local", to, subject, text });
  return { sent: true };
}

export async function sendVerificationEmail(email, link) {
  return sendMail({
    to: email,
    subject: "Verify your Whereabouts email",
    text: `Welcome to Whereabouts.\n\nConfirm this email address to enable location sharing:\n${link}\n\nThis link expires in 24 hours. If you didn't sign up, ignore this message.`,
  });
}
