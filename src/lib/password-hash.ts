import argon2 from 'argon2';

export const hashedPassword = async (password: string) =>
  await argon2.hash(password);

export const comparePassword = async (
  hashedPassword: string,
  password: string
) => await argon2.verify(hashedPassword, password);

let DUMMY_PASSWORD_HASH: string | null = null;

export const getDummyHash = async (): Promise<string> => {
  if (!DUMMY_PASSWORD_HASH) {
    DUMMY_PASSWORD_HASH = await hashedPassword(
      'dummy-password-for-timing-attack-prevention'
    );
  }

  return DUMMY_PASSWORD_HASH;
};
