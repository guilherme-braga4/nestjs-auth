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

  async signIn({ email, password }: LoginDto): Promise<any> {
    //Add trativas de erro, incluindo a tratativa de usuário não encontrado
    const {
      id,
      name: _name,
      email: _email,
      password: _password,
    } = await this.usersService.findOne(email);

    //Compara as senha criptografada recebida com a senha criptografada do DB
    if (password !== _password) {
      throw new UnauthorizedException();
    }

    const payload = {
      id: id,
      email: _email,
    };

    return {
      id: id,
      name: _name,
      email: _email,
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
      password: encryptedText.toString('base64'),
    };

    const { name, email } = await this.usersService.create(encryptedUser);

    return {
      name: name,
      email: email,
    };
  }
}
