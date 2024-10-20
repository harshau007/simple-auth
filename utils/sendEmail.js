import { createTransport } from "nodemailer";

const transporter = createTransport(
  {
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "79facb17c87b12",
      pass: "94a80d649c31ca",
    },
  },
  {
    secure: false,
  }
);

export async function sendResetPasswordEmail(to, resetURL) {
  const mailOptions = {
    from: `${process.env.FROM_NAME} ${process.env.FROM_EMAIL}`,
    to,
    subject: "Password Reset Request",
    html: `
      <h1>Password Reset</h1>
      <p>You have requested to reset your password. Click the link below to reset it:</p>
      <a href="${resetURL}">Reset Password</a>
      <p>If you didn't request this, please ignore this email.</p>
    `,
  };

  await transporter.sendMail(mailOptions);
}
