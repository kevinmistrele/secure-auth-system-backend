import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

/**
 * Sends transactional mail via SMTP when SMTP_USER/SMTP_PASS are configured;
 * otherwise logs the link so local development needs no mail account.
 */
@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly transporter?: nodemailer.Transporter;
  private readonly from?: string;

  constructor(config: ConfigService) {
    const user = config.get<string>('SMTP_USER');
    const pass = config.get<string>('SMTP_PASS');
    if (user && pass) {
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user, pass },
      });
      this.from = user;
    }
  }

  async send(to: string, subject: string, text: string): Promise<void> {
    if (!this.transporter) {
      this.logger.log(`[mail disabled] To: ${to} | ${subject} | ${text}`);
      return;
    }
    await this.transporter.sendMail({ from: this.from, to, subject, text });
  }
}
