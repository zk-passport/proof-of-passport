export function getFirstName(mrz: string): string {
  const names = mrz.split("<<");
  const firstName = names[1].split("<")[0].trim();
  const capitalized = firstName.charAt(0) + firstName.slice(1).toLowerCase();
  return capitalized || "Unknown";
}

export function formatDuration(durationInMs: number) {
  const durationInSeconds = durationInMs / 1000;
  const minutes = Math.floor((durationInSeconds % 3600) / 60);
  const seconds = Math.floor(durationInSeconds % 60);

  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}
export function checkInputs(
  passportNumber: string,
  dateOfBirth: string,
  dateOfExpiry: string,
): { success: boolean, message: string } {
  // if (passportNumber.length !== 9) {
  //   throw new Error('Passport number must be 9 characters long');
  // }
  if (dateOfBirth.length !== 6) {
    return {
      success: false,
      message: 'Scan your passport with your camera first'
    };
  }
  if (dateOfExpiry.length !== 6) {
    return {
      success: false,
      message: 'Date of expiry must be 6 characters long'
    };
  }

  return {
    success: true,
    message: ''
  };
}
