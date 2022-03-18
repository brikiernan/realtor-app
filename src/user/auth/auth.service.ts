import { ConflictException, HttpException, Injectable } from '@nestjs/common';
import { UserType } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { PrismaService } from 'src/prisma/prisma.service';

interface SignupParams {
  email: string;
  name: string;
  password: string;
  phone: string;
}

interface SigninParams {
  email: string;
  password: string;
}

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

  private getJWT(email: string, id: number, name: string) {
    return jwt.sign({ email, id, name }, process.env.JSON_TOKEN_KEY, {
      expiresIn: '7d',
    });
  }

  async signup(params: SignupParams, userType: UserType) {
    const { password } = params;

    const userExists = await this.prismaService.user.findUnique({
      where: { email: params.email },
    });

    if (userExists) throw new ConflictException('user already exists');

    const hashedPassword = await bcrypt.hash(password, 10);

    const { email, id, name } = await this.prismaService.user.create({
      data: { ...params, password: hashedPassword, user_type: userType },
    });

    return { token: this.getJWT(email, id, name) };
  }

  async signin({ email, password }: SigninParams) {
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (!user) throw new HttpException('user not found', 404);
    const hashedPassword = user.password;
    const isValidPassword = await bcrypt.compare(password, hashedPassword);
    if (!isValidPassword) throw new HttpException('invalid password', 400);

    return { token: this.getJWT(email, user.id, user.name) };
  }

  getProductKey(email: string, userType: UserType) {
    const string = `${email}-${userType}-${process.env.PRODUCT_KEY_SECRET}`;

    return bcrypt.hash(string, 10);
  }
}
