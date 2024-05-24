use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Finite}
use aiken/list
use aiken/transaction.{ScriptContext, Spend, Transaction, ValidityRange}
use aiken/transaction/credential.{VerificationKey}

type Datum {
  /// POSIX time in seconds, e.g. 1672843961000
  lock_until: POSIXTime,
  /// Owner's credential
  owner: VerificationKeyHash,
  /// Beneficiary's credential
  beneficiary: VerificationKeyHash,
}

type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

type POSIXTime =
  Int

validator {
  fn vesting(datum: Datum, _redeemer: Void, ctx: ScriptContext) -> Bool {
    when ctx.purpose is {
      Spend(_) -> or {
          must_be_signed_by(ctx.transaction, datum.owner),
          and {
            must_be_signed_by(ctx.transaction, datum.beneficiary),
            must_start_after(ctx.transaction.validity_range, datum.lock_until),
          },
        }
      _ -> False
    }
  }
}

fn must_be_signed_by(
  transaction tx: Transaction,
  verification_key_hash vkh: VerificationKeyHash,
) -> Bool {
  list.has(tx.extra_signatories, vkh)
}

fn must_start_after(
  validity_range: ValidityRange,
  lock_expiration_time: POSIXTime,
) -> Bool {
  when validity_range.lower_bound.bound_type is {
    Finite(tx_earliest_time) -> lock_expiration_time <= tx_earliest_time
    _ -> False
  }
}

test must_start_after_succeed_when_lower_bound_is_after() {
  must_start_after(interval.after(2), 1)
}

test must_start_after_succeed_when_lower_bound_is_equal() {
  must_start_after(interval.after(2), 2)
}

test must_start_after_fail_when_lower_bound_is_before() {
  !must_start_after(interval.after(2), 3)
}
