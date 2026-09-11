use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod solana_sandbox_counter {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.authority = ctx.accounts.authority.key();
        counter.count = 0;
        counter.bump = ctx.bumps.counter;
        msg!("SolanaSandboxCounter inicializado com sucesso para autoridade: {:?}", counter.authority);
        Ok(())
    }

    pub fn increment(ctx: Context<Increment>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        // Prevenção estrita de Integer Overflow via checked_add
        counter.count = counter
            .count
            .checked_add(1)
            .ok_or(error!(ErrorCode::CounterOverflow))?;
        msg!("Contador incrementado. Novo valor: {}", counter.count);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 1,
        seeds = [b"counter", authority.key().as_ref()],
        bump
    )]
    pub counter: Account<'info, UserCounter>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Increment<'info> {
    #[account(
        mut,
        seeds = [b"counter", authority.key().as_ref()],
        bump = counter.bump,
        has_one = authority
    )]
    pub counter: Account<'info, UserCounter>,
    pub authority: Signer<'info>,
}

#[account]
pub struct UserCounter {
    pub authority: Pubkey,
    pub count: u64,
    pub bump: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Operação aritmética de incremento excedeu o limite máximo (Overflow).")]
    CounterOverflow,
}
