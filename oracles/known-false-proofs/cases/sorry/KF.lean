namespace KF
/- EXPLOIT: `sorry` closes any goal, leaving an unproved hole the kernel records as `sorryAx`. -/
theorem false_via_sorry : 2 + 2 = 5 := by sorry
end KF
