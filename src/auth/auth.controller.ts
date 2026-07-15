import { Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Public } from '../common/decorators/public.decorator';
import { AuthenticatedUser } from '../common/types/authenticated-user';
import { AuthService, AuthSession } from './auth.service';
import { LoginDto } from './dto/login.dto';
import {
  RequestPasswordResetDto,
  ResetPasswordDto,
} from './dto/password-reset.dto';
import { RefreshDto } from './dto/refresh.dto';
import { RegisterDto } from './dto/register.dto';
import { SwitchTenantDto } from './dto/switch-tenant.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  register(@Body() dto: RegisterDto): Promise<AuthSession> {
    return this.authService.register(dto);
  }

  @Public()
  @HttpCode(200)
  @Post('login')
  login(@Body() dto: LoginDto): Promise<AuthSession> {
    return this.authService.login(dto);
  }

  @Public()
  @HttpCode(200)
  @Post('refresh')
  refresh(@Body() dto: RefreshDto): Promise<AuthSession> {
    return this.authService.refresh(dto.refreshToken);
  }

  @Public()
  @HttpCode(200)
  @Post('logout')
  async logout(@Body() dto: RefreshDto): Promise<{ message: string }> {
    await this.authService.logout(dto.refreshToken);
    return { message: 'Logged out' };
  }

  @HttpCode(200)
  @Post('switch-tenant')
  switchTenant(
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: SwitchTenantDto,
  ): Promise<AuthSession> {
    return this.authService.switchTenant(user, dto);
  }

  @Get('me')
  me(
    @CurrentUser() user: AuthenticatedUser,
  ): Promise<Omit<AuthSession, 'accessToken' | 'refreshToken'>> {
    return this.authService.me(user);
  }

  @Public()
  @HttpCode(200)
  @Post('request-password-reset')
  async requestPasswordReset(
    @Body() dto: RequestPasswordResetDto,
  ): Promise<{ success: boolean; message: string }> {
    await this.authService.requestPasswordReset(dto.email);
    return {
      success: true,
      message: 'If the email exists, a reset link has been sent',
    };
  }

  @Public()
  @HttpCode(200)
  @Post('reset-password')
  async resetPassword(
    @Body() dto: ResetPasswordDto,
  ): Promise<{ success: boolean; message: string }> {
    await this.authService.resetPassword(dto.token, dto.newPassword);
    return { success: true, message: 'Password updated' };
  }
}
