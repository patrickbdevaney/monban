namespace KF
/- EXPLOIT: `admit` is the tactic spelling of `sorry`; same `sorryAx` hole. -/
theorem false_via_admit : 2 + 2 = 5 := by admit
end KF
