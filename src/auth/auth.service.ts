import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { createCipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';
import {
  LoginDto,
  SignUpDto,
  AuthenticatedUser,
  UserDto,
} from './dtos/auth.dto';
import { jwtConstants, passwordConstants } from './constants/secret';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signIn({
    email,
    password,
  }: LoginDto): Promise<Partial<AuthenticatedUser>> {
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

    //O email estará criptografado no JWT Acess_Token, o que permitirá, portanto, que o JWT seja descriptografado e o e-mail seja revalidado para gerar um Refresh_Token
    const authenticatedUser = await this.generateToken(payload);

    return {
      name: _name,
      ...authenticatedUser,
    };
  }

  async signUp({
    password,
    ...rest
  }: { password: string } & SignUpDto): Promise<Partial<SignUpDto>> {
    const encryptedUser: SignUpDto = {
      ...rest,
      password: await this.encryptPassword(password),
    };

    const { name, email } = await this.usersService.create(encryptedUser);

    return {
      name: name,
      email: email,
    };
  }

  private async encryptPassword(password: string): Promise<string> {
    const iv = randomBytes(16);

    const secret = passwordConstants.secret;
    const key = (await promisify(scrypt)(secret, 'salt', 32)) as Buffer;
    const cipher = createCipheriv('aes-256-ctr', key, iv);

    const encryptedText = Buffer.concat([
      cipher.update(password),
      cipher.final(),
    ]);

    const passwordConvertedToBase64 = encryptedText.toString('base64');
    return passwordConvertedToBase64;
  }

  async generateToken(
    payload: Partial<AuthenticatedUser>,
  ): Promise<Partial<AuthenticatedUser>> {
    const accessToken = await this.jwtService.signAsync(payload);

    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '2h',
      secret: jwtConstants.secret_refresh,
    });

    return {
      id: payload.id,
      email: payload.email,
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  async reauthenticateSession({ refreshToken }: any): Promise<any> {
    //1 - (SEGURANÇA) Validar SE o Token recebido existe
    const payload = await this.validateRefreshToken(refreshToken);

    //2 - Gerar um novo Token
    return await this.generateToken(payload);
  }

  private async validateRefreshToken(refreshToken: string): Promise<UserDto> {
    if (!refreshToken) {
      throw new NotFoundException('This token seems to not belongs any user');
    }

    const email = this.jwtService.decode(refreshToken)['email'];

    const user = await this.usersService.findOne(email);

    if (!user) {
      throw new NotFoundException('User not founded');
    }

    try {
      this.jwtService.verify(refreshToken, {
        secret: jwtConstants.secret_refresh,
      });
      return user;
    } catch (err) {
      if (err.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid Signature');
      }
      if (err.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Expired Token');
      }
      throw new UnauthorizedException(err.name);
    }
  }
}
