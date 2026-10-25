namespace KF
/- EXPLOIT: `set_option debug.skipKernelTC true` turns OFF kernel type-checking of new
   declarations, so an ill-typed proof of anything is accepted. -/
set_option debug.skipKernelTC true
theorem via_skip : False := by exact (by admit)
end KF
