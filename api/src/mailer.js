import nodemailer from 'nodemailer'

export function inviteLink(token) {
  const relative=`/accept-invite?token=${encodeURIComponent(token)}`
  return process.env.PUBLIC_BASE_URL?new URL(relative,process.env.PUBLIC_BASE_URL).toString():relative
}

export function verificationLink(token) {
  const relative=`/verify-email?token=${encodeURIComponent(token)}`
  return process.env.PUBLIC_BASE_URL?new URL(relative,process.env.PUBLIC_BASE_URL).toString():relative
}

async function sendEmail(email,subject,text,{requirePublicUrl=false}={}) {
  if(!process.env.SMTP_HOST)return false
  if(!process.env.SMTP_FROM||requirePublicUrl&&!process.env.PUBLIC_BASE_URL)throw new Error('SMTP_FROM is required; invitation and verification email also require PUBLIC_BASE_URL')
  if(process.env.PUBLIC_BASE_URL&&process.env.NODE_ENV==='production'&&new URL(process.env.PUBLIC_BASE_URL).protocol!=='https:')throw new Error('PUBLIC_BASE_URL must use HTTPS in production')
  const port=Number(process.env.SMTP_PORT||587)
  const transporter=nodemailer.createTransport({
    host:process.env.SMTP_HOST,port,secure:port===465,requireTLS:port!==465,
    auth:process.env.SMTP_USER?{user:process.env.SMTP_USER,pass:process.env.SMTP_PASSWORD||''}:undefined,
    connectionTimeout:10_000,greetingTimeout:10_000,socketTimeout:15_000,
    tls:{minVersion:'TLSv1.2'}
  })
  await transporter.sendMail({from:process.env.SMTP_FROM,to:email,subject,text})
  return true
}

export const deliverInvite=(email,token)=>sendEmail(email,'Your WinFire Secure invitation',`You have been invited to WinFire Secure. Set your password using this link:\n\n${inviteLink(token)}\n\nThe link expires in seven days.`,{requirePublicUrl:true})
export const deliverVerification=(email,token)=>sendEmail(email,'Verify your WinFire Secure email',`Verify this email address for your WinFire Secure account:\n\n${verificationLink(token)}\n\nThe link expires in one day. If you did not request this change, ignore this message.`,{requirePublicUrl:true})
export const deliverAlert=(email,title,body)=>sendEmail(email,`WinFire Secure: ${title}`,`${body}\n\nOpen WinFire Secure to review the event.`)
