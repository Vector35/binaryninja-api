; ModuleID = 'lifttest'
source_filename = "lifttest"

; Function Attrs: nofree norecurse nosync nounwind readnone
define i64 @main(i32 %0) local_unnamed_addr #0 {
"0":
  %.not1 = icmp sgt i32 %0, 0
  %1 = mul i32 %0, 10
  %spec.select = select i1 %.not1, i32 %1, i32 0
  %2 = zext i32 %spec.select to i64
  ret i64 %2
}

attributes #0 = { nofree norecurse nosync nounwind readnone }
