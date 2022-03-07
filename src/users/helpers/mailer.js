require("react")
require("dotenv").config();
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.GMAIL_SMTP_HOST,
  port: process.env.GMAIL_SMTP_PORT,
  auth: {
    user: process.env.GMAIL_SMTP_AUTH_USER,
    pass: process.env.GMAIL_SMTP_AUTH_PASSWORD,
  },
});
transporter.verify().then().catch(console.error);

async function sendEmail(email, code, req) {
  let link = process.env.HOST_PREFIX + "://" + process.env.HOST + ":" + process.env.HOST_PORT + "/users/api/auth/activate?email=" + email + "&code=" + code;

  // The body of the email for recipients
  const body_html = `<!DOCTYPE> 
    <html>
      <body>
        <p>Your activation link is code is : </p> <a href="${link}">${link}</a>
      </body>
    </html>`;

  try {
    transporter.sendMail({
      from: process.env.PROJECT_NAME,
      to: email,
      subject: `Complete your registration`, // Subject line
      text: `Hello ${email}, please complete your registration by clicking on the link below`,
      html: body_html
    }).then(info => {
      console.log({info});
    }).catch(console.error);
    return { error: false };
  } catch (error) {
    console.error("send-email-error", error);
    return {
      error: true,
      message: "Cannot send email",
    };
  }
}

module.exports = { sendEmail };
