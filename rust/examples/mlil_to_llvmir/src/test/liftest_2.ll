; ModuleID = 'lifttest'
source_filename = "lifttest"

@BN_GLOBAL_0x100003fac = global [11 x i8] c"lifttest2\0A\00"

; Function Attrs: nofree nounwind
define i64 @main() local_unnamed_addr #0 {
"0":
  %0 = tail call i64 @printf(i8* nonnull dereferenceable(1) getelementptr inbounds ([11 x i8], [11 x i8]* @BN_GLOBAL_0x100003fac, i64 0, i64 0))
  ret i64 0
}

; Function Attrs: nofree nounwind
declare noundef i64 @printf(i8* nocapture noundef readonly) local_unnamed_addr #0

attributes #0 = { nofree nounwind }
