import * as cookie from 'cookie';
import * as cookieSignature from 'cookie-signature';

function decodeSignedCookie(
  cookieHeader: string,
  cookieName: string,
): string | false {
  const rawCookie = cookieHeader
    .split(';')
    .find((part) => part.trim().startsWith(`${cookieName}=`));

  if (!rawCookie) return false;

  const parsed = cookie.parse(rawCookie);
  const encodedValue = parsed[cookieName];

  if (!encodedValue) return false;

  const decoded = decodeURIComponent(encodedValue);
  if (!decoded.startsWith('s:')) return false;

  return cookieSignature.unsign(decoded.slice(2), process.env.COOKIE_SECRET);
}

export default decodeSignedCookie;
