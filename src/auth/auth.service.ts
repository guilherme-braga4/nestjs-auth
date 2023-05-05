import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { createCipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';
import { LoginDto, SignUpDto, SignUpEncryptedDto } from './dtos/auth.dto';
import { jwtConstants } from './constants/secret';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signIn({ email }: LoginDto): Promise<any> {
    const { id, email: _email } = await this.usersService.findOne(email);

    const payload = {
      id: id,
      email: _email,
    };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async signUp({
    password,
    ...rest
  }: { password: Buffer } & SignUpDto): Promise<Partial<User>> {
    const iv = randomBytes(16);

    const secret = jwtConstants.secret;
    const key = (await promisify(scrypt)(secret, 'salt', 32)) as Buffer;
    const cipher = createCipheriv('aes-256-ctr', key, iv);

    const encryptedText = Buffer.concat([
      cipher.update(password),
      cipher.final(),
    ]);

    const encryptedUser: SignUpEncryptedDto = {
      ...rest,
      password: encryptedText,
    };

    const createdUser = await this.usersService.create(encryptedUser);
    return createdUser;
  }
}
