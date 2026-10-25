namespace KF
/- EXPLOIT: `unsafe` lets you write code the kernel never type-checks; `opaque` introduces a
   constant with a hidden body. Combined (an unsafe producer behind an opaque front) they
   smuggle unchecked values into otherwise-"safe" proofs. Both tokens are banned. -/
opaque mystery : Nat
unsafe def danger : Nat := danger
end KF
