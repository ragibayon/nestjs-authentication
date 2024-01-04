import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthRepository } from './auth.repository';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UsersService } from '../user/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { IAuth } from './schema/auth.schema';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

interface IPayload {
  sub: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async registerUser(registerUserDto: RegisterUserDto) {
    const { password } = registerUserDto;
    const hashedPassword = await this.generateHash(password);
    registerUserDto.password = hashedPassword;
    const user = await this.userService.createUser(registerUserDto);
    await this.authRepository.create({ user: user.id });
    return user;
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    const user = await this.userService.findUserByEmail(email);
    const isPasswordMatched = await this.isHashVerified(
      password,
      user.password,
    );
    if (!user || !isPasswordMatched) {
      throw new UnauthorizedException('Invalid Credentials');
    }
    const payload = { sub: user._id.toString() };
    const { accessToken, refreshToken } = await this.generateTokens(payload);

    await this.updateRefreshToken({ user: user._id }, refreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refresh(refreshTokenDto: RefreshTokenDto) {
    const { refresh_token: refreshTokenFromUser } = refreshTokenDto;

    const userId = await this.verifyJwt(refreshTokenFromUser);
    const user = await this.userService.findUserById(userId);

    if (!user) {
      throw new BadRequestException('Invalid refresh token');
    }

    const auth = await this.authRepository.findOne({ user: user._id });

    if (!auth) {
      throw new InternalServerErrorException('Auth data not found');
    }

    this.validateRefreshToken(auth, refreshTokenFromUser);

    const payload = { sub: user._id.toString() };
    const { accessToken, refreshToken } = await this.generateTokens(payload);

    await this.updateRefreshToken({ _id: auth._id }, refreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async changeUserPassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
  ) {
    const { oldPassword, newPassword } = changePasswordDto;
    const user = await this.userService.findUserById(userId);
    const isPasswordMatched = await this.isHashVerified(
      oldPassword,
      user.password,
    );
    if (!isPasswordMatched) {
      throw new BadRequestException('Invalid Credentials');
    }
    const newHashedPassword = await this.generateHash(newPassword);

    await this.userService.updateUserPassword(userId, newHashedPassword);

    this.updateRefreshToken({ user: user._id }, null);
  }

  async forgotUserPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.userService.findUserByEmail(email);
    if (!user) {
      return;
    }
    //generate token
    const payload = { sub: user._id };
    const passwordResetToken = await this.generatePasswordResetToken(payload);

    await this.authRepository.findOneAndUpdate(
      { user: user._id },
      { passwordResetToken },
    );
    return { passwordResetToken };
  }

  async resetUserPassword(
    passwordResetToken,
    resetPasswordDto: ResetPasswordDto,
  ) {
    const userId = await this.verifyJwt(passwordResetToken);
    const auth = await this.authRepository.findOne({ user: userId });
    if (auth.passwordResetToken !== passwordResetToken) {
      throw new BadRequestException('Invalid Password Reset Token');
    }
    const { newPassword } = resetPasswordDto;
    const hashedPassword = await this.generateHash(newPassword);
    await this.userService.updateUserPassword(userId, hashedPassword);
    await this.authRepository.findByIdAndUpdate(auth._id.toString(), {
      passwordResetToken: null,
    });
  }

  private async generateHash(plaintext: string, saltRounds: number = 10) {
    return await bcrypt.hash(plaintext, saltRounds);
  }

  private async isHashVerified(plaintext: string, hash: string) {
    return await bcrypt.compare(plaintext, hash);
  }

  private async generateTokens(payload: IPayload) {
    return {
      accessToken: await this.generateAccessToken(payload),
      refreshToken: await this.generateRefreshToken(payload),
    };
  }

  private async generateAccessToken(payload: object) {
    const jwtSignOptions: JwtSignOptions = {
      expiresIn: 60 * 10,
    };
    return await this.jwtService.signAsync(payload, jwtSignOptions);
  }

  private async generateRefreshToken(payload: object) {
    const jwtSignOptions: JwtSignOptions = {
      expiresIn: 60 * 60 * 24 * 7,
    };
    return await this.jwtService.signAsync(payload, jwtSignOptions);
  }

  private async generatePasswordResetToken(payload: object) {
    const jwtSignOptions: JwtSignOptions = {
      expiresIn: 60 * 10,
    };
    return await this.jwtService.signAsync(payload, jwtSignOptions);
  }

  private async verifyJwt(refreshToken: string) {
    const { sub: userId } = await this.jwtService.verifyAsync(refreshToken);
    if (!userId) {
      throw new BadRequestException('Invalid refresh token payload');
    }
    return userId;
  }

  private validateRefreshToken(auth: IAuth, refreshToken: string) {
    if (auth.refreshToken === null || auth.refreshToken !== refreshToken) {
      throw new BadRequestException(
        'Refresh Token Reused or Invalid refresh token! Please log in',
      );
    }
  }

  private async updateRefreshToken(filter: Object, newRefreshToken: string) {
    await this.authRepository.findOneAndUpdate(filter, {
      refreshToken: newRefreshToken,
    });
  }
}
