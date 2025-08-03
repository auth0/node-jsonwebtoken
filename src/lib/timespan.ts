import ms from 'ms';

export function timespan(time: string | number, iat?: number): number {
  const timestamp = iat || Math.floor(Date.now() / 1000);

  if (typeof time === 'string') {
    try {
      const milliseconds = ms(time);
      if (!milliseconds || isNaN(milliseconds)) {
        return NaN;
      }
      return Math.floor(timestamp + milliseconds / 1000);
    } catch {
      return NaN;
    }
  } else if (typeof time === 'number') {
    return timestamp + time;
  } else {
    return NaN;
  }
}