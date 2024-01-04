import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ChangePasswordDto } from './dto/change-password.dto';
import { User } from '../user/schema/user.schema';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  async registerUser(@Body() registerUserDto: RegisterUserDto) {
    return this.authService.registerUser(registerUserDto);
  }

  @Post('/login')
  async loginUser(@Body() loginUserDto: LoginUserDto) {
    const { accessToken, refreshToken } =
      await this.authService.loginUser(loginUserDto);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  @Post('/refresh')
  async refresh(@Body() refreshTokenDto: RefreshTokenDto) {
    const { accessToken, refreshToken } =
      await this.authService.refresh(refreshTokenDto);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('/change-password')
  @UseGuards(JwtAuthGuard)
  async changeUserPassword(
    @Req() request,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    const { user } = request;
    const { _id: userId } = user;
    await this.authService.changeUserPassword(userId, changePasswordDto);
    return {
      success: true,
      message: 'Password Changed Successfully',
    };
  }
  @HttpCode(HttpStatus.OK)
  @Post('/forgot-password')
  async forgotUserPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotUserPassword(forgotPasswordDto);
  }

  @Post('/reset-password/:passwordResetToken')
  async resetUserPassword(
    @Param('passwordResetToken') passwordResetToken,
    @Body() resetPasswordDto: ResetPasswordDto,
  ) {
    return this.authService.resetUserPassword(
      passwordResetToken,
      resetPasswordDto,
    );
  }
}
