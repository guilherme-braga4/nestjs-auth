import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signIn(emailUser: string, pass: string): Promise<any> {
    const { id, email, password } = await this.usersService.findOne(emailUser);

    if (password !== pass) {
      throw new UnauthorizedException();
    }

    //Implementar JWT
    const payload = {
      id: id,
      email: email,
    };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }
}
