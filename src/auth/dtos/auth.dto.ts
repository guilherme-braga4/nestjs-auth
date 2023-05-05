export class LoginDto {
  email: string;
  password: Buffer;
}

export class SignUpDto {
  name: string;
  email: string;
  password: Buffer;
}

export class SignUpEncryptedDto {
  name: string;
  email: string;
  password: Buffer;
}
