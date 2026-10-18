use rialo_venus_proc_macro::rialo;

rialo! {
    workflow {
        state {
            amount: u64,
            recipient: [u8; 32],
            executed: bool,
        }

        program {
            initiating fn start(
                &mut self,
                amount: u64,
                recipient: rialo_s_program::pubkey::Pubkey,
            ) -> rialo_s_program::entrypoint::ProgramResult {
                self.amount = amount;
                self.recipient = recipient.to_bytes();
                self.executed = false;

                Ok(())
            }
              control fn execute(
                  &mut self,
                  recipient: rialo_s_program::pubkey::Pubkey,
              ) -> rialo_s_program::entrypoint::ProgramResult {
                  if self.executed {
                      return Ok(());
                  }

                  let recipient_account =
                      WriteAccountInfo::from(recipient);

                  let payer_account =
                      &self.accounts[0];

                  let system_program_account =
                      &self.accounts[
                          self.program_rialo_s_program__system_program_index
                      ];

                  let instruction =
                      rialo_s_system_interface::instruction::transfer(
                          payer_account.key,
                          recipient_account.key,
                          self.amount,
                      );

                  rialo_s_program::program::invoke(
                      &instruction,
                      &[
                          payer_account.clone(),
                          recipient_account.clone(),
                          system_program_account.clone(),
                      ],
                  )?;

                  self.executed = true;

                  Ok(())
              }
          }
      }
}

fn main() {
    println!("Rialo AgentPay");
}
