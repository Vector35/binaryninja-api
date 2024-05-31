int8x8_t vadd_s8(int8x8_t a, int8x8_t b);                             // ADD Vd.8B,Vn.8B,Vm.8B
int8x16_t vaddq_s8(int8x16_t a, int8x16_t b);                         // ADD Vd.16B,Vn.16B,Vm.16B
int16x4_t vadd_s16(int16x4_t a, int16x4_t b);                         // ADD Vd.4H,Vn.4H,Vm.4H
int16x8_t vaddq_s16(int16x8_t a, int16x8_t b);                        // ADD Vd.8H,Vn.8H,Vm.8H
int32x2_t vadd_s32(int32x2_t a, int32x2_t b);                         // ADD Vd.2S,Vn.2S,Vm.2S
int32x4_t vaddq_s32(int32x4_t a, int32x4_t b);                        // ADD Vd.4S,Vn.4S,Vm.4S
int64x1_t vadd_s64(int64x1_t a, int64x1_t b);                         // ADD Dd,Dn,Dm
int64x2_t vaddq_s64(int64x2_t a, int64x2_t b);                        // ADD Vd.2D,Vn.2D,Vm.2D
uint8x8_t vadd_u8(uint8x8_t a, uint8x8_t b);                          // ADD Vd.8B,Vn.8B,Vm.8B
uint8x16_t vaddq_u8(uint8x16_t a, uint8x16_t b);                      // ADD Vd.16B,Vn.16B,Vm.16B
uint16x4_t vadd_u16(uint16x4_t a, uint16x4_t b);                      // ADD Vd.4H,Vn.4H,Vm.4H
uint16x8_t vaddq_u16(uint16x8_t a, uint16x8_t b);                     // ADD Vd.8H,Vn.8H,Vm.8H
uint32x2_t vadd_u32(uint32x2_t a, uint32x2_t b);                      // ADD Vd.2S,Vn.2S,Vm.2S
uint32x4_t vaddq_u32(uint32x4_t a, uint32x4_t b);                     // ADD Vd.4S,Vn.4S,Vm.4S
uint64x1_t vadd_u64(uint64x1_t a, uint64x1_t b);                      // ADD Dd,Dn,Dm
uint64x2_t vaddq_u64(uint64x2_t a, uint64x2_t b);                     // ADD Vd.2D,Vn.2D,Vm.2D
float32x2_t vadd_f32(float32x2_t a, float32x2_t b);                   // FADD Vd.2S,Vn.2S,Vm.2S
float32x4_t vaddq_f32(float32x4_t a, float32x4_t b);                  // FADD Vd.4S,Vn.4S,Vm.4S
float64x1_t vadd_f64(float64x1_t a, float64x1_t b);                   // FADD Dd,Dn,Dm
float64x2_t vaddq_f64(float64x2_t a, float64x2_t b);                  // FADD Vd.2D,Vn.2D,Vm.2D
int64_t vaddd_s64(int64_t a, int64_t b);                              // ADD Dd,Dn,Dm
uint64_t vaddd_u64(uint64_t a, uint64_t b);                           // ADD Dd,Dn,Dm
int16x8_t vaddl_s8(int8x8_t a, int8x8_t b);                           // SADDL Vd.8H,Vn.8B,Vm.8B
int32x4_t vaddl_s16(int16x4_t a, int16x4_t b);                        // SADDL Vd.4S,Vn.4H,Vm.4H
int64x2_t vaddl_s32(int32x2_t a, int32x2_t b);                        // SADDL Vd.2D,Vn.2S,Vm.2S
uint16x8_t vaddl_u8(uint8x8_t a, uint8x8_t b);                        // UADDL Vd.8H,Vn.8B,Vm.8B
uint32x4_t vaddl_u16(uint16x4_t a, uint16x4_t b);                     // UADDL Vd.4S,Vn.4H,Vm.4H
uint64x2_t vaddl_u32(uint32x2_t a, uint32x2_t b);                     // UADDL Vd.2D,Vn.2S,Vm.2S
int16x8_t vaddl_high_s8(int8x16_t a, int8x16_t b);                    // SADDL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vaddl_high_s16(int16x8_t a, int16x8_t b);                   // SADDL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vaddl_high_s32(int32x4_t a, int32x4_t b);                   // SADDL2 Vd.2D,Vn.4S,Vm.4S
uint16x8_t vaddl_high_u8(uint8x16_t a, uint8x16_t b);                 // UADDL2 Vd.8H,Vn.16B,Vm.16B
uint32x4_t vaddl_high_u16(uint16x8_t a, uint16x8_t b);                // UADDL2 Vd.4S,Vn.8H,Vm.8H
uint64x2_t vaddl_high_u32(uint32x4_t a, uint32x4_t b);                // UADDL2 Vd.2D,Vn.4S,Vm.4S
int16x8_t vaddw_s8(int16x8_t a, int8x8_t b);                          // SADDW Vd.8H,Vn.8H,Vm.8B
int32x4_t vaddw_s16(int32x4_t a, int16x4_t b);                        // SADDW Vd.4S,Vn.4S,Vm.4H
int64x2_t vaddw_s32(int64x2_t a, int32x2_t b);                        // SADDW Vd.2D,Vn.2D,Vm.2S
uint16x8_t vaddw_u8(uint16x8_t a, uint8x8_t b);                       // UADDW Vd.8H,Vn.8H,Vm.8B
uint32x4_t vaddw_u16(uint32x4_t a, uint16x4_t b);                     // UADDW Vd.4S,Vn.4S,Vm.4H
uint64x2_t vaddw_u32(uint64x2_t a, uint32x2_t b);                     // UADDW Vd.2D,Vn.2D,Vm.2S
int16x8_t vaddw_high_s8(int16x8_t a, int8x16_t b);                    // SADDW2 Vd.8H,Vn.8H,Vm.16B
int32x4_t vaddw_high_s16(int32x4_t a, int16x8_t b);                   // SADDW2 Vd.4S,Vn.4S,Vm.8H
int64x2_t vaddw_high_s32(int64x2_t a, int32x4_t b);                   // SADDW2 Vd.2D,Vn.2D,Vm.4S
uint16x8_t vaddw_high_u8(uint16x8_t a, uint8x16_t b);                 // UADDW2 Vd.8H,Vn.8H,Vm.16B
uint32x4_t vaddw_high_u16(uint32x4_t a, uint16x8_t b);                // UADDW2 Vd.4S,Vn.4S,Vm.8H
uint64x2_t vaddw_high_u32(uint64x2_t a, uint32x4_t b);                // UADDW2 Vd.2D,Vn.2D,Vm.4S
int8x8_t vhadd_s8(int8x8_t a, int8x8_t b);                            // SHADD Vd.8B,Vn.8B,Vm.8B
int8x16_t vhaddq_s8(int8x16_t a, int8x16_t b);                        // SHADD Vd.16B,Vn.16B,Vm.16B
int16x4_t vhadd_s16(int16x4_t a, int16x4_t b);                        // SHADD Vd.4H,Vn.4H,Vm.4H
int16x8_t vhaddq_s16(int16x8_t a, int16x8_t b);                       // SHADD Vd.8H,Vn.8H,Vm.8H
int32x2_t vhadd_s32(int32x2_t a, int32x2_t b);                        // SHADD Vd.2S,Vn.2S,Vm.2S
int32x4_t vhaddq_s32(int32x4_t a, int32x4_t b);                       // SHADD Vd.4S,Vn.4S,Vm.4S
uint8x8_t vhadd_u8(uint8x8_t a, uint8x8_t b);                         // UHADD Vd.8B,Vn.8B,Vm.8B
uint8x16_t vhaddq_u8(uint8x16_t a, uint8x16_t b);                     // UHADD Vd.16B,Vn.16B,Vm.16B
uint16x4_t vhadd_u16(uint16x4_t a, uint16x4_t b);                     // UHADD Vd.4H,Vn.4H,Vm.4H
uint16x8_t vhaddq_u16(uint16x8_t a, uint16x8_t b);                    // UHADD Vd.8H,Vn.8H,Vm.8H
uint32x2_t vhadd_u32(uint32x2_t a, uint32x2_t b);                     // UHADD Vd.2S,Vn.2S,Vm.2S
uint32x4_t vhaddq_u32(uint32x4_t a, uint32x4_t b);                    // UHADD Vd.4S,Vn.4S,Vm.4S
int8x8_t vrhadd_s8(int8x8_t a, int8x8_t b);                           // SRHADD Vd.8B,Vn.8B,Vm.8B
int8x16_t vrhaddq_s8(int8x16_t a, int8x16_t b);                       // SRHADD Vd.16B,Vn.16B,Vm.16B
int16x4_t vrhadd_s16(int16x4_t a, int16x4_t b);                       // SRHADD Vd.4H,Vn.4H,Vm.4H
int16x8_t vrhaddq_s16(int16x8_t a, int16x8_t b);                      // SRHADD Vd.8H,Vn.8H,Vm.8H
int32x2_t vrhadd_s32(int32x2_t a, int32x2_t b);                       // SRHADD Vd.2S,Vn.2S,Vm.2S
int32x4_t vrhaddq_s32(int32x4_t a, int32x4_t b);                      // SRHADD Vd.4S,Vn.4S,Vm.4S
uint8x8_t vrhadd_u8(uint8x8_t a, uint8x8_t b);                        // URHADD Vd.8B,Vn.8B,Vm.8B
uint8x16_t vrhaddq_u8(uint8x16_t a, uint8x16_t b);                    // URHADD Vd.16B,Vn.16B,Vm.16B
uint16x4_t vrhadd_u16(uint16x4_t a, uint16x4_t b);                    // URHADD Vd.4H,Vn.4H,Vm.4H
uint16x8_t vrhaddq_u16(uint16x8_t a, uint16x8_t b);                   // URHADD Vd.8H,Vn.8H,Vm.8H
uint32x2_t vrhadd_u32(uint32x2_t a, uint32x2_t b);                    // URHADD Vd.2S,Vn.2S,Vm.2S
uint32x4_t vrhaddq_u32(uint32x4_t a, uint32x4_t b);                   // URHADD Vd.4S,Vn.4S,Vm.4S
int8x8_t vqadd_s8(int8x8_t a, int8x8_t b);                            // SQADD Vd.8B,Vn.8B,Vm.8B
int8x16_t vqaddq_s8(int8x16_t a, int8x16_t b);                        // SQADD Vd.16B,Vn.16B,Vm.16B
int16x4_t vqadd_s16(int16x4_t a, int16x4_t b);                        // SQADD Vd.4H,Vn.4H,Vm.4H
int16x8_t vqaddq_s16(int16x8_t a, int16x8_t b);                       // SQADD Vd.8H,Vn.8H,Vm.8H
int32x2_t vqadd_s32(int32x2_t a, int32x2_t b);                        // SQADD Vd.2S,Vn.2S,Vm.2S
int32x4_t vqaddq_s32(int32x4_t a, int32x4_t b);                       // SQADD Vd.4S,Vn.4S,Vm.4S
int64x1_t vqadd_s64(int64x1_t a, int64x1_t b);                        // SQADD Dd,Dn,Dm
int64x2_t vqaddq_s64(int64x2_t a, int64x2_t b);                       // SQADD Vd.2D,Vn.2D,Vm.2D
uint8x8_t vqadd_u8(uint8x8_t a, uint8x8_t b);                         // UQADD Vd.8B,Vn.8B,Vm.8B
uint8x16_t vqaddq_u8(uint8x16_t a, uint8x16_t b);                     // UQADD Vd.16B,Vn.16B,Vm.16B
uint16x4_t vqadd_u16(uint16x4_t a, uint16x4_t b);                     // UQADD Vd.4H,Vn.4H,Vm.4H
uint16x8_t vqaddq_u16(uint16x8_t a, uint16x8_t b);                    // UQADD Vd.8H,Vn.8H,Vm.8H
uint32x2_t vqadd_u32(uint32x2_t a, uint32x2_t b);                     // UQADD Vd.2S,Vn.2S,Vm.2S
uint32x4_t vqaddq_u32(uint32x4_t a, uint32x4_t b);                    // UQADD Vd.4S,Vn.4S,Vm.4S
uint64x1_t vqadd_u64(uint64x1_t a, uint64x1_t b);                     // UQADD Dd,Dn,Dm
uint64x2_t vqaddq_u64(uint64x2_t a, uint64x2_t b);                    // UQADD Vd.2D,Vn.2D,Vm.2D
int8_t vqaddb_s8(int8_t a, int8_t b);                                 // SQADD Bd,Bn,Bm
int16_t vqaddh_s16(int16_t a, int16_t b);                             // SQADD Hd,Hn,Hm
int32_t vqadds_s32(int32_t a, int32_t b);                             // SQADD Sd,Sn,Sm
int64_t vqaddd_s64(int64_t a, int64_t b);                             // SQADD Dd,Dn,Dm
uint8_t vqaddb_u8(uint8_t a, uint8_t b);                              // UQADD Bd,Bn,Bm
uint16_t vqaddh_u16(uint16_t a, uint16_t b);                          // UQADD Hd,Hn,Hm
uint32_t vqadds_u32(uint32_t a, uint32_t b);                          // UQADD Sd,Sn,Sm
uint64_t vqaddd_u64(uint64_t a, uint64_t b);                          // UQADD Dd,Dn,Dm
int8x8_t vuqadd_s8(int8x8_t a, uint8x8_t b);                          // SUQADD Vd.8B,Vn.8B
int8x16_t vuqaddq_s8(int8x16_t a, uint8x16_t b);                      // SUQADD Vd.16B,Vn.16B
int16x4_t vuqadd_s16(int16x4_t a, uint16x4_t b);                      // SUQADD Vd.4H,Vn.4H
int16x8_t vuqaddq_s16(int16x8_t a, uint16x8_t b);                     // SUQADD Vd.8H,Vn.8H
int32x2_t vuqadd_s32(int32x2_t a, uint32x2_t b);                      // SUQADD Vd.2S,Vn.2S
int32x4_t vuqaddq_s32(int32x4_t a, uint32x4_t b);                     // SUQADD Vd.4S,Vn.4S
int64x1_t vuqadd_s64(int64x1_t a, uint64x1_t b);                      // SUQADD Dd,Dn
int64x2_t vuqaddq_s64(int64x2_t a, uint64x2_t b);                     // SUQADD Vd.2D,Vn.2D
int8_t vuqaddb_s8(int8_t a, uint8_t b);                               // SUQADD Bd,Bn
int16_t vuqaddh_s16(int16_t a, uint16_t b);                           // SUQADD Hd,Hn
int32_t vuqadds_s32(int32_t a, uint32_t b);                           // SUQADD Sd,Sn
int64_t vuqaddd_s64(int64_t a, uint64_t b);                           // SUQADD Dd,Dn
uint8x8_t vsqadd_u8(uint8x8_t a, int8x8_t b);                         // USQADD Vd.8B,Vn.8B
uint8x16_t vsqaddq_u8(uint8x16_t a, int8x16_t b);                     // USQADD Vd.16B,Vn.16B
uint16x4_t vsqadd_u16(uint16x4_t a, int16x4_t b);                     // USQADD Vd.4H,Vn.4H
uint16x8_t vsqaddq_u16(uint16x8_t a, int16x8_t b);                    // USQADD Vd.8H,Vn.8H
uint32x2_t vsqadd_u32(uint32x2_t a, int32x2_t b);                     // USQADD Vd.2S,Vn.2S
uint32x4_t vsqaddq_u32(uint32x4_t a, int32x4_t b);                    // USQADD Vd.4S,Vn.4S
uint64x1_t vsqadd_u64(uint64x1_t a, int64x1_t b);                     // USQADD Dd,Dn
uint64x2_t vsqaddq_u64(uint64x2_t a, int64x2_t b);                    // USQADD Vd.2D,Vn.2D
uint8_t vsqaddb_u8(uint8_t a, int8_t b);                              // USQADD Bd,Bn
uint16_t vsqaddh_u16(uint16_t a, int16_t b);                          // USQADD Hd,Hn
uint32_t vsqadds_u32(uint32_t a, int32_t b);                          // USQADD Sd,Sn
uint64_t vsqaddd_u64(uint64_t a, int64_t b);                          // USQADD Dd,Dn
int8x8_t vaddhn_s16(int16x8_t a, int16x8_t b);                        // ADDHN Vd.8B,Vn.8H,Vm.8H
int16x4_t vaddhn_s32(int32x4_t a, int32x4_t b);                       // ADDHN Vd.4H,Vn.4S,Vm.4S
int32x2_t vaddhn_s64(int64x2_t a, int64x2_t b);                       // ADDHN Vd.2S,Vn.2D,Vm.2D
uint8x8_t vaddhn_u16(uint16x8_t a, uint16x8_t b);                     // ADDHN Vd.8B,Vn.8H,Vm.8H
uint16x4_t vaddhn_u32(uint32x4_t a, uint32x4_t b);                    // ADDHN Vd.4H,Vn.4S,Vm.4S
uint32x2_t vaddhn_u64(uint64x2_t a, uint64x2_t b);                    // ADDHN Vd.2S,Vn.2D,Vm.2D
int8x16_t vaddhn_high_s16(int8x8_t r, int16x8_t a, int16x8_t b);      // ADDHN2 Vd.16B,Vn.8H,Vm.8H
int16x8_t vaddhn_high_s32(int16x4_t r, int32x4_t a, int32x4_t b);     // ADDHN2 Vd.8H,Vn.4S,Vm.4S
int32x4_t vaddhn_high_s64(int32x2_t r, int64x2_t a, int64x2_t b);     // ADDHN2 Vd.4S,Vn.2D,Vm.2D
uint8x16_t vaddhn_high_u16(uint8x8_t r, uint16x8_t a, uint16x8_t b);  // ADDHN2 Vd.16B,Vn.8H,Vm.8H
uint16x8_t vaddhn_high_u32(uint16x4_t r, uint32x4_t a, uint32x4_t b);  // ADDHN2 Vd.8H,Vn.4S,Vm.4S
uint32x4_t vaddhn_high_u64(uint32x2_t r, uint64x2_t a, uint64x2_t b);  // ADDHN2 Vd.4S,Vn.2D,Vm.2D
int8x8_t vraddhn_s16(int16x8_t a, int16x8_t b);                        // RADDHN Vd.8B,Vn.8H,Vm.8H
int16x4_t vraddhn_s32(int32x4_t a, int32x4_t b);                       // RADDHN Vd.4H,Vn.4S,Vm.4S
int32x2_t vraddhn_s64(int64x2_t a, int64x2_t b);                       // RADDHN Vd.2S,Vn.2D,Vm.2D
uint8x8_t vraddhn_u16(uint16x8_t a, uint16x8_t b);                     // RADDHN Vd.8B,Vn.8H,Vm.8H
uint16x4_t vraddhn_u32(uint32x4_t a, uint32x4_t b);                    // RADDHN Vd.4H,Vn.4S,Vm.4S
uint32x2_t vraddhn_u64(uint64x2_t a, uint64x2_t b);                    // RADDHN Vd.2S,Vn.2D,Vm.2D
int8x16_t vraddhn_high_s16(int8x8_t r, int16x8_t a, int16x8_t b);      // RADDHN2 Vd.16B,Vn.8H,Vm.8H
int16x8_t vraddhn_high_s32(int16x4_t r, int32x4_t a, int32x4_t b);     // RADDHN2 Vd.8H,Vn.4S,Vm.4S
int32x4_t vraddhn_high_s64(int32x2_t r, int64x2_t a, int64x2_t b);     // RADDHN2 Vd.4S,Vn.2D,Vm.2D
uint8x16_t vraddhn_high_u16(uint8x8_t r, uint16x8_t a, uint16x8_t b);  // RADDHN2 Vd.16B,Vn.8H,Vm.8H
uint16x8_t vraddhn_high_u32(uint16x4_t r, uint32x4_t a, uint32x4_t b);  // RADDHN2 Vd.8H,Vn.4S,Vm.4S
uint32x4_t vraddhn_high_u64(uint32x2_t r, uint64x2_t a, uint64x2_t b);  // RADDHN2 Vd.4S,Vn.2D,Vm.2D
int8x8_t vmul_s8(int8x8_t a, int8x8_t b);                               // MUL Vd.8B,Vn.8B,Vm.8B
int8x16_t vmulq_s8(int8x16_t a, int8x16_t b);                           // MUL Vd.16B,Vn.16B,Vm.16B
int16x4_t vmul_s16(int16x4_t a, int16x4_t b);                           // MUL Vd.4H,Vn.4H,Vm.4H
int16x8_t vmulq_s16(int16x8_t a, int16x8_t b);                          // MUL Vd.8H,Vn.8H,Vm.8H
int32x2_t vmul_s32(int32x2_t a, int32x2_t b);                           // MUL Vd.2S,Vn.2S,Vm.2S
int32x4_t vmulq_s32(int32x4_t a, int32x4_t b);                          // MUL Vd.4S,Vn.4S,Vm.4S
uint8x8_t vmul_u8(uint8x8_t a, uint8x8_t b);                            // MUL Vd.8B,Vn.8B,Vm.8B
uint8x16_t vmulq_u8(uint8x16_t a, uint8x16_t b);                        // MUL Vd.16B,Vn.16B,Vm.16B
uint16x4_t vmul_u16(uint16x4_t a, uint16x4_t b);                        // MUL Vd.4H,Vn.4H,Vm.4H
uint16x8_t vmulq_u16(uint16x8_t a, uint16x8_t b);                       // MUL Vd.8H,Vn.8H,Vm.8H
uint32x2_t vmul_u32(uint32x2_t a, uint32x2_t b);                        // MUL Vd.2S,Vn.2S,Vm.2S
uint32x4_t vmulq_u32(uint32x4_t a, uint32x4_t b);                       // MUL Vd.4S,Vn.4S,Vm.4S
float32x2_t vmul_f32(float32x2_t a, float32x2_t b);                     // FMUL Vd.2S,Vn.2S,Vm.2S
float32x4_t vmulq_f32(float32x4_t a, float32x4_t b);                    // FMUL Vd.4S,Vn.4S,Vm.4S
poly8x8_t vmul_p8(poly8x8_t a, poly8x8_t b);                            // PMUL Vd.8B,Vn.8B,Vm.8B
poly8x16_t vmulq_p8(poly8x16_t a, poly8x16_t b);                        // PMUL Vd.16B,Vn.16B,Vm.16B
float64x1_t vmul_f64(float64x1_t a, float64x1_t b);                     // FMUL Dd,Dn,Dm
float64x2_t vmulq_f64(float64x2_t a, float64x2_t b);                    // FMUL Vd.2D,Vn.2D,Vm.2D
float32x2_t vmulx_f32(float32x2_t a, float32x2_t b);                    // FMULX Vd.2S,Vn.2S,Vm.2S
float32x4_t vmulxq_f32(float32x4_t a, float32x4_t b);                   // FMULX Vd.4S,Vn.4S,Vm.4S
float64x1_t vmulx_f64(float64x1_t a, float64x1_t b);                    // FMULX Dd,Dn,Dm
float64x2_t vmulxq_f64(float64x2_t a, float64x2_t b);                   // FMULX Vd.2D,Vn.2D,Vm.2D
float32_t vmulxs_f32(float32_t a, float32_t b);                         // FMULX Sd,Sn,Sm
float64_t vmulxd_f64(float64_t a, float64_t b);                         // FMULX Dd,Dn,Dm
float32x2_t vmulx_lane_f32(
    float32x2_t a, float32x2_t v, const int lane);  // FMULX Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vmulxq_lane_f32(
    float32x4_t a, float32x2_t v, const int lane);  // FMULX Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vmulx_lane_f64(float64x1_t a, float64x1_t v, const int lane);  // FMULX Dd,Dn,Vm.D[lane]
float64x2_t vmulxq_lane_f64(
    float64x2_t a, float64x1_t v, const int lane);  // FMULX Vd.2D,Vn.2D,Vm.D[lane]
float32_t vmulxs_lane_f32(float32_t a, float32x2_t v, const int lane);  // FMULX Sd,Sn,Vm.S[lane]
float64_t vmulxd_lane_f64(float64_t a, float64x1_t v, const int lane);  // FMULX Dd,Dn,Vm.D[lane]
float32x2_t vmulx_laneq_f32(
    float32x2_t a, float32x4_t v, const int lane);  // FMULX Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vmulxq_laneq_f32(
    float32x4_t a, float32x4_t v, const int lane);  // FMULX Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vmulx_laneq_f64(
    float64x1_t a, float64x2_t v, const int lane);  // FMULX Dd,Dn,Vm.D[lane]
float64x2_t vmulxq_laneq_f64(
    float64x2_t a, float64x2_t v, const int lane);  // FMULX Vd.2D,Vn.2D,Vm.D[lane]
float32_t vmulxs_laneq_f32(float32_t a, float32x4_t v, const int lane);  // FMULX Sd,Sn,Vm.S[lane]
float64_t vmulxd_laneq_f64(float64_t a, float64x2_t v, const int lane);  // FMULX Dd,Dn,Vm.D[lane]
float32x2_t vdiv_f32(float32x2_t a, float32x2_t b);                      // FDIV Vd.2S,Vn.2S,Vm.2S
float32x4_t vdivq_f32(float32x4_t a, float32x4_t b);                     // FDIV Vd.4S,Vn.4S,Vm.4S
float64x1_t vdiv_f64(float64x1_t a, float64x1_t b);                      // FDIV Dd,Dn,Dm
float64x2_t vdivq_f64(float64x2_t a, float64x2_t b);                     // FDIV Vd.2D,Vn.2D,Vm.2D
int8x8_t vmla_s8(int8x8_t a, int8x8_t b, int8x8_t c);                    // MLA Vd.8B,Vn.8B,Vm.8B
int8x16_t vmlaq_s8(int8x16_t a, int8x16_t b, int8x16_t c);               // MLA Vd.16B,Vn.16B,Vm.16B
int16x4_t vmla_s16(int16x4_t a, int16x4_t b, int16x4_t c);               // MLA Vd.4H,Vn.4H,Vm.4H
int16x8_t vmlaq_s16(int16x8_t a, int16x8_t b, int16x8_t c);              // MLA Vd.8H,Vn.8H,Vm.8H
int32x2_t vmla_s32(int32x2_t a, int32x2_t b, int32x2_t c);               // MLA Vd.2S,Vn.2S,Vm.2S
int32x4_t vmlaq_s32(int32x4_t a, int32x4_t b, int32x4_t c);              // MLA Vd.4S,Vn.4S,Vm.4S
uint8x8_t vmla_u8(uint8x8_t a, uint8x8_t b, uint8x8_t c);                // MLA Vd.8B,Vn.8B,Vm.8B
uint8x16_t vmlaq_u8(uint8x16_t a, uint8x16_t b, uint8x16_t c);           // MLA Vd.16B,Vn.16B,Vm.16B
uint16x4_t vmla_u16(uint16x4_t a, uint16x4_t b, uint16x4_t c);           // MLA Vd.4H,Vn.4H,Vm.4H
uint16x8_t vmlaq_u16(uint16x8_t a, uint16x8_t b, uint16x8_t c);          // MLA Vd.8H,Vn.8H,Vm.8H
uint32x2_t vmla_u32(uint32x2_t a, uint32x2_t b, uint32x2_t c);           // MLA Vd.2S,Vn.2S,Vm.2S
uint32x4_t vmlaq_u32(uint32x4_t a, uint32x4_t b, uint32x4_t c);          // MLA Vd.4S,Vn.4S,Vm.4S
float32x2_t vmla_f32(float32x2_t a, float32x2_t b,
    float32x2_t c);  // RESULT[I] = a[i] + (b[i] * c[i]) for i = 0 to 1
float32x4_t vmlaq_f32(float32x4_t a, float32x4_t b,
    float32x4_t c);  // RESULT[I] = a[i] + (b[i] * c[i]) for i = 0 to 3
float64x1_t vmla_f64(
    float64x1_t a, float64x1_t b, float64x1_t c);  // RESULT[I] = a[i] + (b[i] * c[i]) for i = 0
float64x2_t vmlaq_f64(float64x2_t a, float64x2_t b,
    float64x2_t c);  // RESULT[I] = a[i] + (b[i] * c[i]) for i = 0 to 1
int16x8_t vmlal_s8(int16x8_t a, int8x8_t b, int8x8_t c);              // SMLAL Vd.8H,Vn.8B,Vm.8B
int32x4_t vmlal_s16(int32x4_t a, int16x4_t b, int16x4_t c);           // SMLAL Vd.4S,Vn.4H,Vm.4H
int64x2_t vmlal_s32(int64x2_t a, int32x2_t b, int32x2_t c);           // SMLAL Vd.2D,Vn.2S,Vm.2S
uint16x8_t vmlal_u8(uint16x8_t a, uint8x8_t b, uint8x8_t c);          // UMLAL Vd.8H,Vn.8B,Vm.8B
uint32x4_t vmlal_u16(uint32x4_t a, uint16x4_t b, uint16x4_t c);       // UMLAL Vd.4S,Vn.4H,Vm.4H
uint64x2_t vmlal_u32(uint64x2_t a, uint32x2_t b, uint32x2_t c);       // UMLAL Vd.2D,Vn.2S,Vm.2S
int16x8_t vmlal_high_s8(int16x8_t a, int8x16_t b, int8x16_t c);       // SMLAL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vmlal_high_s16(int32x4_t a, int16x8_t b, int16x8_t c);      // SMLAL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vmlal_high_s32(int64x2_t a, int32x4_t b, int32x4_t c);      // SMLAL2 Vd.2D,Vn.4S,Vm.4S
uint16x8_t vmlal_high_u8(uint16x8_t a, uint8x16_t b, uint8x16_t c);   // UMLAL2 Vd.8H,Vn.16B,Vm.16B
uint32x4_t vmlal_high_u16(uint32x4_t a, uint16x8_t b, uint16x8_t c);  // UMLAL2 Vd.4S,Vn.8H,Vm.8H
uint64x2_t vmlal_high_u32(uint64x2_t a, uint32x4_t b, uint32x4_t c);  // UMLAL2 Vd.2D,Vn.4S,Vm.4S
int8x8_t vmls_s8(int8x8_t a, int8x8_t b, int8x8_t c);                 // MLS Vd.8B,Vn.8B,Vm.8B
int8x16_t vmlsq_s8(int8x16_t a, int8x16_t b, int8x16_t c);            // MLS Vd.16B,Vn.16B,Vm.16B
int16x4_t vmls_s16(int16x4_t a, int16x4_t b, int16x4_t c);            // MLS Vd.4H,Vn.4H,Vm.4H
int16x8_t vmlsq_s16(int16x8_t a, int16x8_t b, int16x8_t c);           // MLS Vd.8H,Vn.8H,Vm.8H
int32x2_t vmls_s32(int32x2_t a, int32x2_t b, int32x2_t c);            // MLS Vd.2S,Vn.2S,Vm.2S
int32x4_t vmlsq_s32(int32x4_t a, int32x4_t b, int32x4_t c);           // MLS Vd.4S,Vn.4S,Vm.4S
uint8x8_t vmls_u8(uint8x8_t a, uint8x8_t b, uint8x8_t c);             // MLS Vd.8B,Vn.8B,Vm.8B
uint8x16_t vmlsq_u8(uint8x16_t a, uint8x16_t b, uint8x16_t c);        // MLS Vd.16B,Vn.16B,Vm.16B
uint16x4_t vmls_u16(uint16x4_t a, uint16x4_t b, uint16x4_t c);        // MLS Vd.4H,Vn.4H,Vm.4H
uint16x8_t vmlsq_u16(uint16x8_t a, uint16x8_t b, uint16x8_t c);       // MLS Vd.8H,Vn.8H,Vm.8H
uint32x2_t vmls_u32(uint32x2_t a, uint32x2_t b, uint32x2_t c);        // MLS Vd.2S,Vn.2S,Vm.2S
uint32x4_t vmlsq_u32(uint32x4_t a, uint32x4_t b, uint32x4_t c);       // MLS Vd.4S,Vn.4S,Vm.4S
float32x2_t vmls_f32(float32x2_t a, float32x2_t b,
    float32x2_t c);  // RESULT[I] = a[i] - (b[i] * c[i]) for i = 0 to 1
float32x4_t vmlsq_f32(float32x4_t a, float32x4_t b,
    float32x4_t c);  // RESULT[I] = a[i] - (b[i] * c[i]) for i = 0 to 3
float64x1_t vmls_f64(
    float64x1_t a, float64x1_t b, float64x1_t c);  // RESULT[I] = a[i] - (b[i] * c[i]) for i = 0
float64x2_t vmlsq_f64(float64x2_t a, float64x2_t b,
    float64x2_t c);  // RESULT[I] = a[i] - (b[i] * c[i]) for i = 0 to 1
int16x8_t vmlsl_s8(int16x8_t a, int8x8_t b, int8x8_t c);              // SMLSL Vd.8H,Vn.8B,Vm.8B
int32x4_t vmlsl_s16(int32x4_t a, int16x4_t b, int16x4_t c);           // SMLSL Vd.4S,Vn.4H,Vm.4H
int64x2_t vmlsl_s32(int64x2_t a, int32x2_t b, int32x2_t c);           // SMLSL Vd.2D,Vn.2S,Vm.2S
uint16x8_t vmlsl_u8(uint16x8_t a, uint8x8_t b, uint8x8_t c);          // UMLSL Vd.8H,Vn.8B,Vm.8B
uint32x4_t vmlsl_u16(uint32x4_t a, uint16x4_t b, uint16x4_t c);       // UMLSL Vd.4S,Vn.4H,Vm.4H
uint64x2_t vmlsl_u32(uint64x2_t a, uint32x2_t b, uint32x2_t c);       // UMLSL Vd.2D,Vn.2S,Vm.2S
int16x8_t vmlsl_high_s8(int16x8_t a, int8x16_t b, int8x16_t c);       // SMLSL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vmlsl_high_s16(int32x4_t a, int16x8_t b, int16x8_t c);      // SMLSL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vmlsl_high_s32(int64x2_t a, int32x4_t b, int32x4_t c);      // SMLSL2 Vd.2D,Vn.4S,Vm.4S
uint16x8_t vmlsl_high_u8(uint16x8_t a, uint8x16_t b, uint8x16_t c);   // UMLSL2 Vd.8H,Vn.16B,Vm.16B
uint32x4_t vmlsl_high_u16(uint32x4_t a, uint16x8_t b, uint16x8_t c);  // UMLSL2 Vd.4S,Vn.8H,Vm.8H
uint64x2_t vmlsl_high_u32(uint64x2_t a, uint32x4_t b, uint32x4_t c);  // UMLSL2 Vd.2D,Vn.4S,Vm.4S
float32x2_t vfma_f32(float32x2_t a, float32x2_t b, float32x2_t c);    // FMLA Vd.2S,Vn.2S,Vm.2S
float32x4_t vfmaq_f32(float32x4_t a, float32x4_t b, float32x4_t c);   // FMLA Vd.4S,Vn.4S,Vm.4S
float64x1_t vfma_f64(float64x1_t a, float64x1_t b, float64x1_t c);    // FMADD Dd,Dn,Dm,Da
float64x2_t vfmaq_f64(float64x2_t a, float64x2_t b, float64x2_t c);   // FMLA Vd.2D,Vn.2D,Vm.2D
float32x2_t vfma_lane_f32(
    float32x2_t a, float32x2_t b, float32x2_t v, const int lane);  // FMLA Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vfmaq_lane_f32(
    float32x4_t a, float32x4_t b, float32x2_t v, const int lane);  // FMLA Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vfma_lane_f64(
    float64x1_t a, float64x1_t b, float64x1_t v, const int lane);  // FMLA Dd,Dn,Vm.D[lane]
float64x2_t vfmaq_lane_f64(
    float64x2_t a, float64x2_t b, float64x1_t v, const int lane);  // FMLA Vd.2D,Vn.2D,Vm.D[lane]
float32_t vfmas_lane_f32(
    float32_t a, float32_t b, float32x2_t v, const int lane);  // FMLA Sd,Sn,Vm.S[lane]
float64_t vfmad_lane_f64(
    float64_t a, float64_t b, float64x1_t v, const int lane);  // FMLA Dd,Dn,Vm.D[lane]
float32x2_t vfma_laneq_f32(
    float32x2_t a, float32x2_t b, float32x4_t v, const int lane);  // FMLA Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vfmaq_laneq_f32(
    float32x4_t a, float32x4_t b, float32x4_t v, const int lane);  // FMLA Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vfma_laneq_f64(
    float64x1_t a, float64x1_t b, float64x2_t v, const int lane);  // FMLA Dd,Dn,Vm.D[lane]
float64x2_t vfmaq_laneq_f64(
    float64x2_t a, float64x2_t b, float64x2_t v, const int lane);  // FMLA Vd.2D,Vn.2D,Vm.D[lane]
float32_t vfmas_laneq_f32(
    float32_t a, float32_t b, float32x4_t v, const int lane);  // FMLA Sd,Sn,Vm.S[lane]
float64_t vfmad_laneq_f64(
    float64_t a, float64_t b, float64x2_t v, const int lane);        // FMLA Dd,Dn,Vm.D[lane]
float32x2_t vfms_f32(float32x2_t a, float32x2_t b, float32x2_t c);   // FMLS Vd.2S,Vn.2S,Vm.2S
float32x4_t vfmsq_f32(float32x4_t a, float32x4_t b, float32x4_t c);  // FMLS Vd.4S,Vn.4S,Vm.4S
float64x1_t vfms_f64(float64x1_t a, float64x1_t b, float64x1_t c);   // FMSUB Dd,Dn,Dm,Da
float64x2_t vfmsq_f64(float64x2_t a, float64x2_t b, float64x2_t c);  // FMLS Vd.2D,Vn.2D,Vm.2D
float32x2_t vfms_lane_f32(
    float32x2_t a, float32x2_t b, float32x2_t v, const int lane);  // FMLS Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vfmsq_lane_f32(
    float32x4_t a, float32x4_t b, float32x2_t v, const int lane);  // FMLS Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vfms_lane_f64(
    float64x1_t a, float64x1_t b, float64x1_t v, const int lane);  // FMLS Dd,Dn,Vm.D[lane]
float64x2_t vfmsq_lane_f64(
    float64x2_t a, float64x2_t b, float64x1_t v, const int lane);  // FMLS Vd.2D,Vn.2D,Vm.D[lane]
float32_t vfmss_lane_f32(
    float32_t a, float32_t b, float32x2_t v, const int lane);  // FMLS Sd,Sn,Vm.S[lane]
float64_t vfmsd_lane_f64(
    float64_t a, float64_t b, float64x1_t v, const int lane);  // FMLS Dd,Dn,Vm.D[lane]
float32x2_t vfms_laneq_f32(
    float32x2_t a, float32x2_t b, float32x4_t v, const int lane);  // FMLS Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vfmsq_laneq_f32(
    float32x4_t a, float32x4_t b, float32x4_t v, const int lane);  // FMLS Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vfms_laneq_f64(
    float64x1_t a, float64x1_t b, float64x2_t v, const int lane);  // FMLS Dd,Dn,Vm.D[lane]
float64x2_t vfmsq_laneq_f64(
    float64x2_t a, float64x2_t b, float64x2_t v, const int lane);  // FMLS Vd.2D,Vn.2D,Vm.D[lane]
float32_t vfmss_laneq_f32(
    float32_t a, float32_t b, float32x4_t v, const int lane);  // FMLS Sd,Sn,Vm.S[lane]
float64_t vfmsd_laneq_f64(
    float64_t a, float64_t b, float64x2_t v, const int lane);          // FMLS Dd,Dn,Vm.D[lane]
int16x4_t vqdmulh_s16(int16x4_t a, int16x4_t b);                       // SQDMULH Vd.4H,Vn.4H,Vm.4H
int16x8_t vqdmulhq_s16(int16x8_t a, int16x8_t b);                      // SQDMULH Vd.8H,Vn.8H,Vm.8H
int32x2_t vqdmulh_s32(int32x2_t a, int32x2_t b);                       // SQDMULH Vd.2S,Vn.2S,Vm.2S
int32x4_t vqdmulhq_s32(int32x4_t a, int32x4_t b);                      // SQDMULH Vd.4S,Vn.4S,Vm.4S
int16_t vqdmulhh_s16(int16_t a, int16_t b);                            // SQDMULH Hd,Hn,Hm
int32_t vqdmulhs_s32(int32_t a, int32_t b);                            // SQDMULH Sd,Sn,Sm
int16x4_t vqrdmulh_s16(int16x4_t a, int16x4_t b);                      // SQRDMULH Vd.4H,Vn.4H,Vm.4H
int16x8_t vqrdmulhq_s16(int16x8_t a, int16x8_t b);                     // SQRDMULH Vd.8H,Vn.8H,Vm.8H
int32x2_t vqrdmulh_s32(int32x2_t a, int32x2_t b);                      // SQRDMULH Vd.2S,Vn.2S,Vm.2S
int32x4_t vqrdmulhq_s32(int32x4_t a, int32x4_t b);                     // SQRDMULH Vd.4S,Vn.4S,Vm.4S
int16_t vqrdmulhh_s16(int16_t a, int16_t b);                           // SQRDMULH Hd,Hn,Hm
int32_t vqrdmulhs_s32(int32_t a, int32_t b);                           // SQRDMULH Sd,Sn,Sm
int32x4_t vqdmlal_s16(int32x4_t a, int16x4_t b, int16x4_t c);          // SQDMLAL Vd.4S,Vn.4H,Vm.4H
int64x2_t vqdmlal_s32(int64x2_t a, int32x2_t b, int32x2_t c);          // SQDMLAL Vd.2D,Vn.2S,Vm.2S
int32_t vqdmlalh_s16(int32_t a, int16_t b, int16_t c);                 // SQDMLAL Sd,Hn,Hm
int64_t vqdmlals_s32(int64_t a, int32_t b, int32_t c);                 // SQDMLAL Dd,Sn,Sm
int32x4_t vqdmlal_high_s16(int32x4_t a, int16x8_t b, int16x8_t c);     // SQDMLAL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vqdmlal_high_s32(int64x2_t a, int32x4_t b, int32x4_t c);     // SQDMLAL2 Vd.2D,Vn.4S,Vm.4S
int32x4_t vqdmlsl_s16(int32x4_t a, int16x4_t b, int16x4_t c);          // SQDMLSL Vd.4S,Vn.4H,Vm.4H
int64x2_t vqdmlsl_s32(int64x2_t a, int32x2_t b, int32x2_t c);          // SQDMLSL Vd.2D,Vn.2S,Vm.2S
int32_t vqdmlslh_s16(int32_t a, int16_t b, int16_t c);                 // SQDMLSL Sd,Hn,Hm
int64_t vqdmlsls_s32(int64_t a, int32_t b, int32_t c);                 // SQDMLSL Dd,Sn,Sm
int32x4_t vqdmlsl_high_s16(int32x4_t a, int16x8_t b, int16x8_t c);     // SQDMLSL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vqdmlsl_high_s32(int64x2_t a, int32x4_t b, int32x4_t c);     // SQDMLSL2 Vd.2D,Vn.4S,Vm.4S
int16x8_t vmull_s8(int8x8_t a, int8x8_t b);                            // SMULL Vd.8H,Vn.8B,Vm.8B
int32x4_t vmull_s16(int16x4_t a, int16x4_t b);                         // SMULL Vd.4S,Vn.4H,Vm.4H
int64x2_t vmull_s32(int32x2_t a, int32x2_t b);                         // SMULL Vd.2D,Vn.2S,Vm.2S
uint16x8_t vmull_u8(uint8x8_t a, uint8x8_t b);                         // UMULL Vd.8H,Vn.8B,Vm.8B
uint32x4_t vmull_u16(uint16x4_t a, uint16x4_t b);                      // UMULL Vd.4S,Vn.4H,Vm.4H
uint64x2_t vmull_u32(uint32x2_t a, uint32x2_t b);                      // UMULL Vd.2D,Vn.2S,Vm.2S
poly16x8_t vmull_p8(poly8x8_t a, poly8x8_t b);                         // PMULL Vd.8H,Vn.8B,Vm.8B
int16x8_t vmull_high_s8(int8x16_t a, int8x16_t b);                     // SMULL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vmull_high_s16(int16x8_t a, int16x8_t b);                    // SMULL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vmull_high_s32(int32x4_t a, int32x4_t b);                    // SMULL2 Vd.2D,Vn.4S,Vm.4S
uint16x8_t vmull_high_u8(uint8x16_t a, uint8x16_t b);                  // UMULL2 Vd.8H,Vn.16B,Vm.16B
uint32x4_t vmull_high_u16(uint16x8_t a, uint16x8_t b);                 // UMULL2 Vd.4S,Vn.8H,Vm.8H
uint64x2_t vmull_high_u32(uint32x4_t a, uint32x4_t b);                 // UMULL2 Vd.2D,Vn.4S,Vm.4S
poly16x8_t vmull_high_p8(poly8x16_t a, poly8x16_t b);                  // PMULL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vqdmull_s16(int16x4_t a, int16x4_t b);                       // SQDMULL Vd.4S,Vn.4H,Vm.4H
int64x2_t vqdmull_s32(int32x2_t a, int32x2_t b);                       // SQDMULL Vd.2D,Vn.2S,Vm.2S
int32_t vqdmullh_s16(int16_t a, int16_t b);                            // SQDMULL Sd,Hn,Hm
int64_t vqdmulls_s32(int32_t a, int32_t b);                            // SQDMULL Dd,Sn,Sm
int32x4_t vqdmull_high_s16(int16x8_t a, int16x8_t b);                  // SQDMULL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vqdmull_high_s32(int32x4_t a, int32x4_t b);                  // SQDMULL2 Vd.2D,Vn.4S,Vm.4S
int8x8_t vsub_s8(int8x8_t a, int8x8_t b);                              // SUB Vd.8B,Vn.8B,Vm.8B
int8x16_t vsubq_s8(int8x16_t a, int8x16_t b);                          // SUB Vd.16B,Vn.16B,Vm.16B
int16x4_t vsub_s16(int16x4_t a, int16x4_t b);                          // SUB Vd.4H,Vn.4H,Vm.4H
int16x8_t vsubq_s16(int16x8_t a, int16x8_t b);                         // SUB Vd.8H,Vn.8H,Vm.8H
int32x2_t vsub_s32(int32x2_t a, int32x2_t b);                          // SUB Vd.2S,Vn.2S,Vm.2S
int32x4_t vsubq_s32(int32x4_t a, int32x4_t b);                         // SUB Vd.4S,Vn.4S,Vm.4S
int64x1_t vsub_s64(int64x1_t a, int64x1_t b);                          // SUB Dd,Dn,Dm
int64x2_t vsubq_s64(int64x2_t a, int64x2_t b);                         // SUB Vd.2D,Vn.2D,Vm.2D
uint8x8_t vsub_u8(uint8x8_t a, uint8x8_t b);                           // SUB Vd.8B,Vn.8B,Vm.8B
uint8x16_t vsubq_u8(uint8x16_t a, uint8x16_t b);                       // SUB Vd.16B,Vn.16B,Vm.16B
uint16x4_t vsub_u16(uint16x4_t a, uint16x4_t b);                       // SUB Vd.4H,Vn.4H,Vm.4H
uint16x8_t vsubq_u16(uint16x8_t a, uint16x8_t b);                      // SUB Vd.8H,Vn.8H,Vm.8H
uint32x2_t vsub_u32(uint32x2_t a, uint32x2_t b);                       // SUB Vd.2S,Vn.2S,Vm.2S
uint32x4_t vsubq_u32(uint32x4_t a, uint32x4_t b);                      // SUB Vd.4S,Vn.4S,Vm.4S
uint64x1_t vsub_u64(uint64x1_t a, uint64x1_t b);                       // SUB Dd,Dn,Dm
uint64x2_t vsubq_u64(uint64x2_t a, uint64x2_t b);                      // SUB Vd.2D,Vn.2D,Vm.2D
float32x2_t vsub_f32(float32x2_t a, float32x2_t b);                    // FSUB Vd.2S,Vn.2S,Vm.2S
float32x4_t vsubq_f32(float32x4_t a, float32x4_t b);                   // FSUB Vd.4S,Vn.4S,Vm.4S
float64x1_t vsub_f64(float64x1_t a, float64x1_t b);                    // FSUB Dd,Dn,Dm
float64x2_t vsubq_f64(float64x2_t a, float64x2_t b);                   // FSUB Vd.2D,Vn.2D,Vm.2D
int64_t vsubd_s64(int64_t a, int64_t b);                               // SUB Dd,Dn,Dm
uint64_t vsubd_u64(uint64_t a, uint64_t b);                            // SUB Dd,Dn,Dm
int16x8_t vsubl_s8(int8x8_t a, int8x8_t b);                            // SSUBL Vd.8H,Vn.8B,Vm.8B
int32x4_t vsubl_s16(int16x4_t a, int16x4_t b);                         // SSUBL Vd.4S,Vn.4H,Vm.4H
int64x2_t vsubl_s32(int32x2_t a, int32x2_t b);                         // SSUBL Vd.2D,Vn.2S,Vm.2S
uint16x8_t vsubl_u8(uint8x8_t a, uint8x8_t b);                         // USUBL Vd.8H,Vn.8B,Vm.8B
uint32x4_t vsubl_u16(uint16x4_t a, uint16x4_t b);                      // USUBL Vd.4S,Vn.4H,Vm.4H
uint64x2_t vsubl_u32(uint32x2_t a, uint32x2_t b);                      // USUBL Vd.2D,Vn.2S,Vm.2S
int16x8_t vsubl_high_s8(int8x16_t a, int8x16_t b);                     // SSUBL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vsubl_high_s16(int16x8_t a, int16x8_t b);                    // SSUBL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vsubl_high_s32(int32x4_t a, int32x4_t b);                    // SSUBL2 Vd.2D,Vn.4S,Vm.4S
uint16x8_t vsubl_high_u8(uint8x16_t a, uint8x16_t b);                  // USUBL2 Vd.8H,Vn.16B,Vm.16B
uint32x4_t vsubl_high_u16(uint16x8_t a, uint16x8_t b);                 // USUBL2 Vd.4S,Vn.8H,Vm.8H
uint64x2_t vsubl_high_u32(uint32x4_t a, uint32x4_t b);                 // USUBL2 Vd.2D,Vn.4S,Vm.4S
int16x8_t vsubw_s8(int16x8_t a, int8x8_t b);                           // SSUBW Vd.8H,Vn.8H,Vm.8B
int32x4_t vsubw_s16(int32x4_t a, int16x4_t b);                         // SSUBW Vd.4S,Vn.4S,Vm.4H
int64x2_t vsubw_s32(int64x2_t a, int32x2_t b);                         // SSUBW Vd.2D,Vn.2D,Vm.2S
uint16x8_t vsubw_u8(uint16x8_t a, uint8x8_t b);                        // USUBW Vd.8H,Vn.8H,Vm.8B
uint32x4_t vsubw_u16(uint32x4_t a, uint16x4_t b);                      // USUBW Vd.4S,Vn.4S,Vm.4H
uint64x2_t vsubw_u32(uint64x2_t a, uint32x2_t b);                      // USUBW Vd.2D,Vn.2D,Vm.2S
int16x8_t vsubw_high_s8(int16x8_t a, int8x16_t b);                     // SSUBW2 Vd.8H,Vn.8H,Vm.16B
int32x4_t vsubw_high_s16(int32x4_t a, int16x8_t b);                    // SSUBW2 Vd.4S,Vn.4S,Vm.8H
int64x2_t vsubw_high_s32(int64x2_t a, int32x4_t b);                    // SSUBW2 Vd.2D,Vn.2D,Vm.4S
uint16x8_t vsubw_high_u8(uint16x8_t a, uint8x16_t b);                  // USUBW2 Vd.8H,Vn.8H,Vm.16B
uint32x4_t vsubw_high_u16(uint32x4_t a, uint16x8_t b);                 // USUBW2 Vd.4S,Vn.4S,Vm.8H
uint64x2_t vsubw_high_u32(uint64x2_t a, uint32x4_t b);                 // USUBW2 Vd.2D,Vn.2D,Vm.4S
int8x8_t vhsub_s8(int8x8_t a, int8x8_t b);                             // SHSUB Vd.8B,Vn.8B,Vm.8B
int8x16_t vhsubq_s8(int8x16_t a, int8x16_t b);                         // SHSUB Vd.16B,Vn.16B,Vm.16B
int16x4_t vhsub_s16(int16x4_t a, int16x4_t b);                         // SHSUB Vd.4H,Vn.4H,Vm.4H
int16x8_t vhsubq_s16(int16x8_t a, int16x8_t b);                        // SHSUB Vd.8H,Vn.8H,Vm.8H
int32x2_t vhsub_s32(int32x2_t a, int32x2_t b);                         // SHSUB Vd.2S,Vn.2S,Vm.2S
int32x4_t vhsubq_s32(int32x4_t a, int32x4_t b);                        // SHSUB Vd.4S,Vn.4S,Vm.4S
uint8x8_t vhsub_u8(uint8x8_t a, uint8x8_t b);                          // UHSUB Vd.8B,Vn.8B,Vm.8B
uint8x16_t vhsubq_u8(uint8x16_t a, uint8x16_t b);                      // UHSUB Vd.16B,Vn.16B,Vm.16B
uint16x4_t vhsub_u16(uint16x4_t a, uint16x4_t b);                      // UHSUB Vd.4H,Vn.4H,Vm.4H
uint16x8_t vhsubq_u16(uint16x8_t a, uint16x8_t b);                     // UHSUB Vd.8H,Vn.8H,Vm.8H
uint32x2_t vhsub_u32(uint32x2_t a, uint32x2_t b);                      // UHSUB Vd.2S,Vn.2S,Vm.2S
uint32x4_t vhsubq_u32(uint32x4_t a, uint32x4_t b);                     // UHSUB Vd.4S,Vn.4S,Vm.4S
int8x8_t vqsub_s8(int8x8_t a, int8x8_t b);                             // SQSUB Vd.8B,Vn.8B,Vm.8B
int8x16_t vqsubq_s8(int8x16_t a, int8x16_t b);                         // SQSUB Vd.16B,Vn.16B,Vm.16B
int16x4_t vqsub_s16(int16x4_t a, int16x4_t b);                         // SQSUB Vd.4H,Vn.4H,Vm.4H
int16x8_t vqsubq_s16(int16x8_t a, int16x8_t b);                        // SQSUB Vd.8H,Vn.8H,Vm.8H
int32x2_t vqsub_s32(int32x2_t a, int32x2_t b);                         // SQSUB Vd.2S,Vn.2S,Vm.2S
int32x4_t vqsubq_s32(int32x4_t a, int32x4_t b);                        // SQSUB Vd.4S,Vn.4S,Vm.4S
int64x1_t vqsub_s64(int64x1_t a, int64x1_t b);                         // SQSUB Dd,Dn,Dm
int64x2_t vqsubq_s64(int64x2_t a, int64x2_t b);                        // SQSUB Vd.2D,Vn.2D,Vm.2D
uint8x8_t vqsub_u8(uint8x8_t a, uint8x8_t b);                          // UQSUB Vd.8B,Vn.8B,Vm.8B
uint8x16_t vqsubq_u8(uint8x16_t a, uint8x16_t b);                      // UQSUB Vd.16B,Vn.16B,Vm.16B
uint16x4_t vqsub_u16(uint16x4_t a, uint16x4_t b);                      // UQSUB Vd.4H,Vn.4H,Vm.4H
uint16x8_t vqsubq_u16(uint16x8_t a, uint16x8_t b);                     // UQSUB Vd.8H,Vn.8H,Vm.8H
uint32x2_t vqsub_u32(uint32x2_t a, uint32x2_t b);                      // UQSUB Vd.2S,Vn.2S,Vm.2S
uint32x4_t vqsubq_u32(uint32x4_t a, uint32x4_t b);                     // UQSUB Vd.4S,Vn.4S,Vm.4S
uint64x1_t vqsub_u64(uint64x1_t a, uint64x1_t b);                      // UQSUB Dd,Dn,Dm
uint64x2_t vqsubq_u64(uint64x2_t a, uint64x2_t b);                     // UQSUB Vd.2D,Vn.2D,Vm.2D
int8_t vqsubb_s8(int8_t a, int8_t b);                                  // SQSUB Bd,Bn,Bm
int16_t vqsubh_s16(int16_t a, int16_t b);                              // SQSUB Hd,Hn,Hm
int32_t vqsubs_s32(int32_t a, int32_t b);                              // SQSUB Sd,Sn,Sm
int64_t vqsubd_s64(int64_t a, int64_t b);                              // SQSUB Dd,Dn,Dm
uint8_t vqsubb_u8(uint8_t a, uint8_t b);                               // UQSUB Bd,Bn,Bm
uint16_t vqsubh_u16(uint16_t a, uint16_t b);                           // UQSUB Hd,Hn,Hm
uint32_t vqsubs_u32(uint32_t a, uint32_t b);                           // UQSUB Sd,Sn,Sm
uint64_t vqsubd_u64(uint64_t a, uint64_t b);                           // UQSUB Dd,Dn,Dm
int8x8_t vsubhn_s16(int16x8_t a, int16x8_t b);                         // SUBHN Vd.8B,Vn.8H,Vm.8H
int16x4_t vsubhn_s32(int32x4_t a, int32x4_t b);                        // SUBHN Vd.4H,Vn.4S,Vm.4S
int32x2_t vsubhn_s64(int64x2_t a, int64x2_t b);                        // SUBHN Vd.2S,Vn.2D,Vm.2D
uint8x8_t vsubhn_u16(uint16x8_t a, uint16x8_t b);                      // SUBHN Vd.8B,Vn.8H,Vm.8H
uint16x4_t vsubhn_u32(uint32x4_t a, uint32x4_t b);                     // SUBHN Vd.4H,Vn.4S,Vm.4S
uint32x2_t vsubhn_u64(uint64x2_t a, uint64x2_t b);                     // SUBHN Vd.2S,Vn.2D,Vm.2D
int8x16_t vsubhn_high_s16(int8x8_t r, int16x8_t a, int16x8_t b);       // SUBHN2 Vd.16B,Vn.8H,Vm.8H
int16x8_t vsubhn_high_s32(int16x4_t r, int32x4_t a, int32x4_t b);      // SUBHN2 Vd.8H,Vn.4S,Vm.4S
int32x4_t vsubhn_high_s64(int32x2_t r, int64x2_t a, int64x2_t b);      // SUBHN2 Vd.4S,Vn.2D,Vm.2D
uint8x16_t vsubhn_high_u16(uint8x8_t r, uint16x8_t a, uint16x8_t b);   // SUBHN2 Vd.16B,Vn.8H,Vm.8H
uint16x8_t vsubhn_high_u32(uint16x4_t r, uint32x4_t a, uint32x4_t b);  // SUBHN2 Vd.8H,Vn.4S,Vm.4S
uint32x4_t vsubhn_high_u64(uint32x2_t r, uint64x2_t a, uint64x2_t b);  // SUBHN2 Vd.4S,Vn.2D,Vm.2D
int8x8_t vrsubhn_s16(int16x8_t a, int16x8_t b);                        // RSUBHN Vd.8B,Vn.8H,Vm.8H
int16x4_t vrsubhn_s32(int32x4_t a, int32x4_t b);                       // RSUBHN Vd.4H,Vn.4S,Vm.4S
int32x2_t vrsubhn_s64(int64x2_t a, int64x2_t b);                       // RSUBHN Vd.2S,Vn.2D,Vm.2D
uint8x8_t vrsubhn_u16(uint16x8_t a, uint16x8_t b);                     // RSUBHN Vd.8B,Vn.8H,Vm.8H
uint16x4_t vrsubhn_u32(uint32x4_t a, uint32x4_t b);                    // RSUBHN Vd.4H,Vn.4S,Vm.4S
uint32x2_t vrsubhn_u64(uint64x2_t a, uint64x2_t b);                    // RSUBHN Vd.2S,Vn.2D,Vm.2D
int8x16_t vrsubhn_high_s16(int8x8_t r, int16x8_t a, int16x8_t b);      // RSUBHN2 Vd.16B,Vn.8H,Vm.8H
int16x8_t vrsubhn_high_s32(int16x4_t r, int32x4_t a, int32x4_t b);     // RSUBHN2 Vd.8H,Vn.4S,Vm.4S
int32x4_t vrsubhn_high_s64(int32x2_t r, int64x2_t a, int64x2_t b);     // RSUBHN2 Vd.4S,Vn.2D,Vm.2D
uint8x16_t vrsubhn_high_u16(uint8x8_t r, uint16x8_t a, uint16x8_t b);  // RSUBHN2 Vd.16B,Vn.8H,Vm.8H
uint16x8_t vrsubhn_high_u32(uint16x4_t r, uint32x4_t a, uint32x4_t b);  // RSUBHN2 Vd.8H,Vn.4S,Vm.4S
uint32x4_t vrsubhn_high_u64(uint32x2_t r, uint64x2_t a, uint64x2_t b);  // RSUBHN2 Vd.4S,Vn.2D,Vm.2D
uint8x8_t vceq_s8(int8x8_t a, int8x8_t b);                              // CMEQ Vd.8B,Vn.8B,Vm.8B
uint8x16_t vceqq_s8(int8x16_t a, int8x16_t b);                          // CMEQ Vd.16B,Vn.16B,Vm.16B
uint16x4_t vceq_s16(int16x4_t a, int16x4_t b);                          // CMEQ Vd.4H,Vn.4H,Vm.4H
uint16x8_t vceqq_s16(int16x8_t a, int16x8_t b);                         // CMEQ Vd.8H,Vn.8H,Vm.8H
uint32x2_t vceq_s32(int32x2_t a, int32x2_t b);                          // CMEQ Vd.2S,Vn.2S,Vm.2S
uint32x4_t vceqq_s32(int32x4_t a, int32x4_t b);                         // CMEQ Vd.4S,Vn.4S,Vm.4S
uint8x8_t vceq_u8(uint8x8_t a, uint8x8_t b);                            // CMEQ Vd.8B,Vn.8B,Vm.8B
uint8x16_t vceqq_u8(uint8x16_t a, uint8x16_t b);                        // CMEQ Vd.16B,Vn.16B,Vm.16B
uint16x4_t vceq_u16(uint16x4_t a, uint16x4_t b);                        // CMEQ Vd.4H,Vn.4H,Vm.4H
uint16x8_t vceqq_u16(uint16x8_t a, uint16x8_t b);                       // CMEQ Vd.8H,Vn.8H,Vm.8H
uint32x2_t vceq_u32(uint32x2_t a, uint32x2_t b);                        // CMEQ Vd.2S,Vn.2S,Vm.2S
uint32x4_t vceqq_u32(uint32x4_t a, uint32x4_t b);                       // CMEQ Vd.4S,Vn.4S,Vm.4S
uint32x2_t vceq_f32(float32x2_t a, float32x2_t b);                      // FCMEQ Vd.2S,Vn.2S,Vm.2S
uint32x4_t vceqq_f32(float32x4_t a, float32x4_t b);                     // FCMEQ Vd.4S,Vn.4S,Vm.4S
uint8x8_t vceq_p8(poly8x8_t a, poly8x8_t b);                            // CMEQ Vd.8B,Vn.8B,Vm.8B
uint8x16_t vceqq_p8(poly8x16_t a, poly8x16_t b);                        // CMEQ Vd.16B,Vn.16B,Vm.16B
uint64x1_t vceq_s64(int64x1_t a, int64x1_t b);                          // CMEQ Dd,Dn,Dm
uint64x2_t vceqq_s64(int64x2_t a, int64x2_t b);                         // CMEQ Vd.2D,Vn.2D,Vm.2D
uint64x1_t vceq_u64(uint64x1_t a, uint64x1_t b);                        // CMEQ Dd,Dn,Dm
uint64x2_t vceqq_u64(uint64x2_t a, uint64x2_t b);                       // CMEQ Vd.2D,Vn.2D,Vm.2D
uint64x1_t vceq_p64(poly64x1_t a, poly64x1_t b);                        // CMEQ Dd,Dn,Dm
uint64x2_t vceqq_p64(poly64x2_t a, poly64x2_t b);                       // CMEQ Vd.2D,Vn.2D,Vm.2D
uint64x1_t vceq_f64(float64x1_t a, float64x1_t b);                      // FCMEQ Dd,Dn,Dm
uint64x2_t vceqq_f64(float64x2_t a, float64x2_t b);                     // FCMEQ Vd.2D,Vn.2D,Vm.2D
uint64_t vceqd_s64(int64_t a, int64_t b);                               // CMEQ Dd,Dn,Dm
uint64_t vceqd_u64(uint64_t a, uint64_t b);                             // CMEQ Dd,Dn,Dm
uint32_t vceqs_f32(float32_t a, float32_t b);                           // FCMEQ Sd,Sn,Sm
uint64_t vceqd_f64(float64_t a, float64_t b);                           // FCMEQ Dd,Dn,Dm
uint8x8_t vceqz_s8(int8x8_t a);                                         // CMEQ Vd.8B,Vn.8B,#0
uint8x16_t vceqzq_s8(int8x16_t a);                                      // CMEQ Vd.16B,Vn.16B,#0
uint16x4_t vceqz_s16(int16x4_t a);                                      // CMEQ Vd.4H,Vn.4H,#0
uint16x8_t vceqzq_s16(int16x8_t a);                                     // CMEQ Vd.8H,Vn.8H,#0
uint32x2_t vceqz_s32(int32x2_t a);                                      // CMEQ Vd.2S,Vn.2S,#0
uint32x4_t vceqzq_s32(int32x4_t a);                                     // CMEQ Vd.4S,Vn.4S,#0
uint8x8_t vceqz_u8(uint8x8_t a);                                        // CMEQ Vd.8B,Vn.8B,#0
uint8x16_t vceqzq_u8(uint8x16_t a);                                     // CMEQ Vd.16B,Vn.16B,#0
uint16x4_t vceqz_u16(uint16x4_t a);                                     // CMEQ Vd.4H,Vn.4H,#0
uint16x8_t vceqzq_u16(uint16x8_t a);                                    // CMEQ Vd.8H,Vn.8H,#0
uint32x2_t vceqz_u32(uint32x2_t a);                                     // CMEQ Vd.2S,Vn.2S,#0
uint32x4_t vceqzq_u32(uint32x4_t a);                                    // CMEQ Vd.4S,Vn.4S,#0
uint32x2_t vceqz_f32(float32x2_t a);                                    // FCMEQ Vd.2S,Vn.2S,#0
uint32x4_t vceqzq_f32(float32x4_t a);                                   // FCMEQ Vd.4S,Vn.4S,#0
uint8x8_t vceqz_p8(poly8x8_t a);                                        // CMEQ Vd.8B,Vn.8B,#0
uint8x16_t vceqzq_p8(poly8x16_t a);                                     // CMEQ Vd.16B,Vn.16B,#0
uint64x1_t vceqz_s64(int64x1_t a);                                      // CMEQ Dd,Dn,#0
uint64x2_t vceqzq_s64(int64x2_t a);                                     // CMEQ Vd.2D,Vn.2D,#0
uint64x1_t vceqz_u64(uint64x1_t a);                                     // CMEQ Dd,Dn,#0
uint64x2_t vceqzq_u64(uint64x2_t a);                                    // CMEQ Vd.2D,Vn.2D,#0
uint64x1_t vceqz_p64(poly64x1_t a);                                     // CMEQ Dd,Dn,#0
uint64x2_t vceqzq_p64(poly64x2_t a);                                    // CMEQ Vd.2D,Vn.2D,#0
uint64x1_t vceqz_f64(float64x1_t a);                                    // FCMEQ Dd,Dn,#0
uint64x2_t vceqzq_f64(float64x2_t a);                                   // FCMEQ Vd.2D,Vn.2D,#0
uint64_t vceqzd_s64(int64_t a);                                         // CMEQ Dd,Dn,#0
uint64_t vceqzd_u64(uint64_t a);                                        // CMEQ Dd,Dn,#0
uint32_t vceqzs_f32(float32_t a);                                       // FCMEQ Sd,Sn,#0
uint64_t vceqzd_f64(float64_t a);                                       // FCMEQ Dd,Dn,#0
uint8x8_t vcge_s8(int8x8_t a, int8x8_t b);                              // CMGE Vd.8B,Vm.8B,Vn.8B
uint8x16_t vcgeq_s8(int8x16_t a, int8x16_t b);                          // CMGE Vd.16B,Vm.16B,Vn.16B
uint16x4_t vcge_s16(int16x4_t a, int16x4_t b);                          // CMGE Vd.4H,Vm.4H,Vn.4H
uint16x8_t vcgeq_s16(int16x8_t a, int16x8_t b);                         // CMGE Vd.8H,Vm.8H,Vn.8H
uint32x2_t vcge_s32(int32x2_t a, int32x2_t b);                          // CMGE Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcgeq_s32(int32x4_t a, int32x4_t b);                         // CMGE Vd.4S,Vm.4S,Vn.4S
uint8x8_t vcge_u8(uint8x8_t a, uint8x8_t b);                            // CMHS Vd.8B,Vm.8B,Vn.8B
uint8x16_t vcgeq_u8(uint8x16_t a, uint8x16_t b);                        // CMHS Vd.16B,Vm.16B,Vn.16B
uint16x4_t vcge_u16(uint16x4_t a, uint16x4_t b);                        // CMHS Vd.4H,Vm.4H,Vn.4H
uint16x8_t vcgeq_u16(uint16x8_t a, uint16x8_t b);                       // CMHS Vd.8H,Vm.8H,Vn.8H
uint32x2_t vcge_u32(uint32x2_t a, uint32x2_t b);                        // CMHS Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcgeq_u32(uint32x4_t a, uint32x4_t b);                       // CMHS Vd.4S,Vm.4S,Vn.4S
uint32x2_t vcge_f32(float32x2_t a, float32x2_t b);                      // FCMGE Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcgeq_f32(float32x4_t a, float32x4_t b);                     // FCMGE Vd.4S,Vm.4S,Vn.4S
uint64x1_t vcge_s64(int64x1_t a, int64x1_t b);                          // CMGE Dd,Dn,Dm
uint64x2_t vcgeq_s64(int64x2_t a, int64x2_t b);                         // CMGE Vd.2D,Vm.2D,Vn.2D
uint64x1_t vcge_u64(uint64x1_t a, uint64x1_t b);                        // CMHS Dd,Dn,Dm
uint64x2_t vcgeq_u64(uint64x2_t a, uint64x2_t b);                       // CMHS Vd.2D,Vm.2D,Vn.2D
uint64x1_t vcge_f64(float64x1_t a, float64x1_t b);                      // FCMGE Dd,Dn,Dm
uint64x2_t vcgeq_f64(float64x2_t a, float64x2_t b);                     // FCMGE Vd.2D,Vm.2D,Vn.2D
uint64_t vcged_s64(int64_t a, int64_t b);                               // CMGE Dd,Dn,Dm
uint64_t vcged_u64(uint64_t a, uint64_t b);                             // CMHS Dd,Dn,Dm
uint32_t vcges_f32(float32_t a, float32_t b);                           // FCMGE Sd,Sn,Sm
uint64_t vcged_f64(float64_t a, float64_t b);                           // FCMGE Dd,Dn,Dm
uint8x8_t vcgez_s8(int8x8_t a);                                         // CMGE Vd.8B,Vn.8B,#0
uint8x16_t vcgezq_s8(int8x16_t a);                                      // CMGE Vd.16B,Vn.16B,#0
uint16x4_t vcgez_s16(int16x4_t a);                                      // CMGE Vd.4H,Vn.4H,#0
uint16x8_t vcgezq_s16(int16x8_t a);                                     // CMGE Vd.8H,Vn.8H,#0
uint32x2_t vcgez_s32(int32x2_t a);                                      // CMGE Vd.2S,Vn.2S,#0
uint32x4_t vcgezq_s32(int32x4_t a);                                     // CMGE Vd.4S,Vn.4S,#0
uint64x1_t vcgez_s64(int64x1_t a);                                      // CMGE Dd,Dn,#0
uint64x2_t vcgezq_s64(int64x2_t a);                                     // CMGE Vd.2D,Vn.2D,#0
uint32x2_t vcgez_f32(float32x2_t a);                                    // FCMGE Vd.2S,Vn.2S,#0
uint32x4_t vcgezq_f32(float32x4_t a);                                   // FCMGE Vd.4S,Vn.4S,#0
uint64x1_t vcgez_f64(float64x1_t a);                                    // FCMGE Dd,Dn,#0
uint64x2_t vcgezq_f64(float64x2_t a);                                   // FCMGE Vd.2D,Vn.2D,#0
uint64_t vcgezd_s64(int64_t a);                                         // CMGE Dd,Dn,#0
uint32_t vcgezs_f32(float32_t a);                                       // FCMGE Sd,Sn,#0
uint64_t vcgezd_f64(float64_t a);                                       // FCMGE Dd,Dn,#0
uint8x8_t vcle_s8(int8x8_t a, int8x8_t b);                              // CMGE Vd.8B,Vm.8B,Vn.8B
uint8x16_t vcleq_s8(int8x16_t a, int8x16_t b);                          // CMGE Vd.16B,Vm.16B,Vn.16B
uint16x4_t vcle_s16(int16x4_t a, int16x4_t b);                          // CMGE Vd.4H,Vm.4H,Vn.4H
uint16x8_t vcleq_s16(int16x8_t a, int16x8_t b);                         // CMGE Vd.8H,Vm.8H,Vn.8H
uint32x2_t vcle_s32(int32x2_t a, int32x2_t b);                          // CMGE Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcleq_s32(int32x4_t a, int32x4_t b);                         // CMGE Vd.4S,Vm.4S,Vn.4S
uint8x8_t vcle_u8(uint8x8_t a, uint8x8_t b);                            // CMHS Vd.8B,Vm.8B,Vn.8B
uint8x16_t vcleq_u8(uint8x16_t a, uint8x16_t b);                        // CMHS Vd.16B,Vm.16B,Vn.16B
uint16x4_t vcle_u16(uint16x4_t a, uint16x4_t b);                        // CMHS Vd.4H,Vm.4H,Vn.4H
uint16x8_t vcleq_u16(uint16x8_t a, uint16x8_t b);                       // CMHS Vd.8H,Vm.8H,Vn.8H
uint32x2_t vcle_u32(uint32x2_t a, uint32x2_t b);                        // CMHS Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcleq_u32(uint32x4_t a, uint32x4_t b);                       // CMHS Vd.4S,Vm.4S,Vn.4S
uint32x2_t vcle_f32(float32x2_t a, float32x2_t b);                      // FCMGE Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcleq_f32(float32x4_t a, float32x4_t b);                     // FCMGE Vd.4S,Vm.4S,Vn.4S
uint64x1_t vcle_s64(int64x1_t a, int64x1_t b);                          // CMGE Dd,Dm,Dn
uint64x2_t vcleq_s64(int64x2_t a, int64x2_t b);                         // CMGE Vd.2D,Vm.2D,Vn.2D
uint64x1_t vcle_u64(uint64x1_t a, uint64x1_t b);                        // CMHS Dd,Dm,Dn
uint64x2_t vcleq_u64(uint64x2_t a, uint64x2_t b);                       // CMHS Vd.2D,Vm.2D,Vn.2D
uint64x1_t vcle_f64(float64x1_t a, float64x1_t b);                      // FCMGE Dd,Dm,Dn
uint64x2_t vcleq_f64(float64x2_t a, float64x2_t b);                     // FCMGE Vd.2D,Vm.2D,Vn.2D
uint64_t vcled_s64(int64_t a, int64_t b);                               // CMGE Dd,Dm,Dn
uint64_t vcled_u64(uint64_t a, uint64_t b);                             // CMHS Dd,Dm,Dn
uint32_t vcles_f32(float32_t a, float32_t b);                           // FCMGE Sd,Sm,Sn
uint64_t vcled_f64(float64_t a, float64_t b);                           // FCMGE Dd,Dm,Dn
uint8x8_t vclez_s8(int8x8_t a);                                         // CMLE Vd.8B,Vn.8B,#0
uint8x16_t vclezq_s8(int8x16_t a);                                      // CMLE Vd.16B,Vn.16B,#0
uint16x4_t vclez_s16(int16x4_t a);                                      // CMLE Vd.4H,Vn.4H,#0
uint16x8_t vclezq_s16(int16x8_t a);                                     // CMLE Vd.8H,Vn.8H,#0
uint32x2_t vclez_s32(int32x2_t a);                                      // CMLE Vd.2S,Vn.2S,#0
uint32x4_t vclezq_s32(int32x4_t a);                                     // CMLE Vd.4S,Vn.4S,#0
uint64x1_t vclez_s64(int64x1_t a);                                      // CMLE Dd,Dn,#0
uint64x2_t vclezq_s64(int64x2_t a);                                     // CMLE Vd.2D,Vn.2D,#0
uint32x2_t vclez_f32(float32x2_t a);                                    // CMLE Vd.2S,Vn.2S,#0
uint32x4_t vclezq_f32(float32x4_t a);                                   // FCMLE Vd.4S,Vn.4S,#0
uint64x1_t vclez_f64(float64x1_t a);                                    // FCMLE Dd,Dn,#0
uint64x2_t vclezq_f64(float64x2_t a);                                   // FCMLE Vd.2D,Vn.2D,#0
uint64_t vclezd_s64(int64_t a);                                         // CMLE Dd,Dn,#0
uint32_t vclezs_f32(float32_t a);                                       // FCMLE Sd,Sn,#0
uint64_t vclezd_f64(float64_t a);                                       // FCMLE Dd,Dn,#0
uint8x8_t vcgt_s8(int8x8_t a, int8x8_t b);                              // CMGT Vd.8B,Vn.8B,Vm.8B
uint8x16_t vcgtq_s8(int8x16_t a, int8x16_t b);                          // CMGT Vd.16B,Vn.16B,Vm.16B
uint16x4_t vcgt_s16(int16x4_t a, int16x4_t b);                          // CMGT Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcgtq_s16(int16x8_t a, int16x8_t b);                         // CMGT Vd.8H,Vn.8H,Vm.8H
uint32x2_t vcgt_s32(int32x2_t a, int32x2_t b);                          // CMGT Vd.2S,Vn.2S,Vm.2S
uint32x4_t vcgtq_s32(int32x4_t a, int32x4_t b);                         // CMGT Vd.4S,Vn.4S,Vm.4S
uint8x8_t vcgt_u8(uint8x8_t a, uint8x8_t b);                            // CMHI Vd.8B,Vn.8B,Vm.8B
uint8x16_t vcgtq_u8(uint8x16_t a, uint8x16_t b);                        // CMHI Vd.16B,Vn.16B,Vm.16B
uint16x4_t vcgt_u16(uint16x4_t a, uint16x4_t b);                        // CMHI Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcgtq_u16(uint16x8_t a, uint16x8_t b);                       // CMHI Vd.8H,Vn.8H,Vm.8H
uint32x2_t vcgt_u32(uint32x2_t a, uint32x2_t b);                        // CMHI Vd.2S,Vn.2S,Vm.2S
uint32x4_t vcgtq_u32(uint32x4_t a, uint32x4_t b);                       // CMHI Vd.4S,Vn.4S,Vm.4S
uint32x2_t vcgt_f32(float32x2_t a, float32x2_t b);                      // FCMGT Vd.2S,Vn.2S,Vm.2S
uint32x4_t vcgtq_f32(float32x4_t a, float32x4_t b);                     // FCMGT Vd.4S,Vn.4S,Vm.4S
uint64x1_t vcgt_s64(int64x1_t a, int64x1_t b);                          // CMGT Dd,Dn,Dm
uint64x2_t vcgtq_s64(int64x2_t a, int64x2_t b);                         // CMGT Vd.2D,Vn.2D,Vm.2D
uint64x1_t vcgt_u64(uint64x1_t a, uint64x1_t b);                        // CMHI Dd,Dn,Dm
uint64x2_t vcgtq_u64(uint64x2_t a, uint64x2_t b);                       // CMHI Vd.2D,Vn.2D,Vm.2D
uint64x1_t vcgt_f64(float64x1_t a, float64x1_t b);                      // FCMGT Dd,Dn,Dm
uint64x2_t vcgtq_f64(float64x2_t a, float64x2_t b);                     // FCMGT Vd.2D,Vn.2D,Vm.2D
uint64_t vcgtd_s64(int64_t a, int64_t b);                               // CMGT Dd,Dn,Dm
uint64_t vcgtd_u64(uint64_t a, uint64_t b);                             // CMHI Dd,Dn,Dm
uint32_t vcgts_f32(float32_t a, float32_t b);                           // FCMGT Sd,Sn,Sm
uint64_t vcgtd_f64(float64_t a, float64_t b);                           // FCMGT Dd,Dn,Dm
uint8x8_t vcgtz_s8(int8x8_t a);                                         // CMGT Vd.8B,Vn.8B,#0
uint8x16_t vcgtzq_s8(int8x16_t a);                                      // CMGT Vd.16B,Vn.16B,#0
uint16x4_t vcgtz_s16(int16x4_t a);                                      // CMGT Vd.4H,Vn.4H,#0
uint16x8_t vcgtzq_s16(int16x8_t a);                                     // CMGT Vd.8H,Vn.8H,#0
uint32x2_t vcgtz_s32(int32x2_t a);                                      // CMGT Vd.2S,Vn.2S,#0
uint32x4_t vcgtzq_s32(int32x4_t a);                                     // CMGT Vd.4S,Vn.4S,#0
uint64x1_t vcgtz_s64(int64x1_t a);                                      // CMGT Dd,Dn,#0
uint64x2_t vcgtzq_s64(int64x2_t a);                                     // CMGT Vd.2D,Vn.2D,#0
uint32x2_t vcgtz_f32(float32x2_t a);                                    // FCMGT Vd.2S,Vn.2S,#0
uint32x4_t vcgtzq_f32(float32x4_t a);                                   // FCMGT Vd.4S,Vn.4S,#0
uint64x1_t vcgtz_f64(float64x1_t a);                                    // FCMGT Dd,Dn,#0
uint64x2_t vcgtzq_f64(float64x2_t a);                                   // FCMGT Vd.2D,Vn.2D,#0
uint64_t vcgtzd_s64(int64_t a);                                         // CMGT Dd,Dn,#0
uint32_t vcgtzs_f32(float32_t a);                                       // FCMGT Sd,Sn,#0
uint64_t vcgtzd_f64(float64_t a);                                       // FCMGT Dd,Dn,#0
uint8x8_t vclt_s8(int8x8_t a, int8x8_t b);                              // CMGT Vd.8B,Vm.8B,Vn.8B
uint8x16_t vcltq_s8(int8x16_t a, int8x16_t b);                          // CMGT Vd.16B,Vm.16B,Vn.16B
uint16x4_t vclt_s16(int16x4_t a, int16x4_t b);                          // CMGT Vd.4H,Vm.4H,Vn.4H
uint16x8_t vcltq_s16(int16x8_t a, int16x8_t b);                         // CMGT Vd.8H,Vm.8H,Vn.8H
uint32x2_t vclt_s32(int32x2_t a, int32x2_t b);                          // CMGT Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcltq_s32(int32x4_t a, int32x4_t b);                         // CMGT Vd.4S,Vm.4S,Vn.4S
uint8x8_t vclt_u8(uint8x8_t a, uint8x8_t b);                            // CMHI Vd.8B,Vm.8B,Vn.8B
uint8x16_t vcltq_u8(uint8x16_t a, uint8x16_t b);                        // CMHI Vd.16B,Vm.16B,Vn.16B
uint16x4_t vclt_u16(uint16x4_t a, uint16x4_t b);                        // CMHI Vd.4H,Vm.4H,Vn.4H
uint16x8_t vcltq_u16(uint16x8_t a, uint16x8_t b);                       // CMHI Vd.8H,Vm.8H,Vn.8H
uint32x2_t vclt_u32(uint32x2_t a, uint32x2_t b);                        // CMHI Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcltq_u32(uint32x4_t a, uint32x4_t b);                       // CMHI Vd.4S,Vm.4S,Vn.4S
uint32x2_t vclt_f32(float32x2_t a, float32x2_t b);                      // FCMGT Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcltq_f32(float32x4_t a, float32x4_t b);                     // FCMGT Vd.4S,Vm.4S,Vn.4S
uint64x1_t vclt_s64(int64x1_t a, int64x1_t b);                          // CMGT Dd,Dm,Dn
uint64x2_t vcltq_s64(int64x2_t a, int64x2_t b);                         // CMGT Vd.2D,Vm.2D,Vn.2D
uint64x1_t vclt_u64(uint64x1_t a, uint64x1_t b);                        // CMHI Dd,Dm,Dn
uint64x2_t vcltq_u64(uint64x2_t a, uint64x2_t b);                       // CMHI Vd.2D,Vm.2D,Vn.2D
uint64x1_t vclt_f64(float64x1_t a, float64x1_t b);                      // FCMGT Dd,Dm,Dn
uint64x2_t vcltq_f64(float64x2_t a, float64x2_t b);                     // FCMGT Vd.2D,Vm.2D,Vn.2D
uint64_t vcltd_s64(int64_t a, int64_t b);                               // CMGT Dd,Dm,Dn
uint64_t vcltd_u64(uint64_t a, uint64_t b);                             // CMHI Dd,Dm,Dn
uint32_t vclts_f32(float32_t a, float32_t b);                           // FCMGT Sd,Sm,Sn
uint64_t vcltd_f64(float64_t a, float64_t b);                           // FCMGT Dd,Dm,Dn
uint8x8_t vcltz_s8(int8x8_t a);                                         // CMLT Vd.8B,Vn.8B,#0
uint8x16_t vcltzq_s8(int8x16_t a);                                      // CMLT Vd.16B,Vn.16B,#0
uint16x4_t vcltz_s16(int16x4_t a);                                      // CMLT Vd.4H,Vn.4H,#0
uint16x8_t vcltzq_s16(int16x8_t a);                                     // CMLT Vd.8H,Vn.8H,#0
uint32x2_t vcltz_s32(int32x2_t a);                                      // CMLT Vd.2S,Vn.2S,#0
uint32x4_t vcltzq_s32(int32x4_t a);                                     // CMLT Vd.4S,Vn.4S,#0
uint64x1_t vcltz_s64(int64x1_t a);                                      // CMLT Dd,Dn,#0
uint64x2_t vcltzq_s64(int64x2_t a);                                     // CMLT Vd.2D,Vn.2D,#0
uint32x2_t vcltz_f32(float32x2_t a);                                    // FCMLT Vd.2S,Vn.2S,#0
uint32x4_t vcltzq_f32(float32x4_t a);                                   // FCMLT Vd.4S,Vn.4S,#0
uint64x1_t vcltz_f64(float64x1_t a);                                    // FCMLT Dd,Dn,#0
uint64x2_t vcltzq_f64(float64x2_t a);                                   // FCMLT Vd.2D,Vn.2D,#0
uint64_t vcltzd_s64(int64_t a);                                         // CMLT Dd,Dn,#0
uint32_t vcltzs_f32(float32_t a);                                       // FCMLT Sd,Sn,#0
uint64_t vcltzd_f64(float64_t a);                                       // FCMLT Dd,Dn,#0
uint32x2_t vcage_f32(float32x2_t a, float32x2_t b);                     // FACGE Vd.2S,Vn.2S,Vm.2S
uint32x4_t vcageq_f32(float32x4_t a, float32x4_t b);                    // FACGE Vd.4S,Vn.4S,Vm.4S
uint64x1_t vcage_f64(float64x1_t a, float64x1_t b);                     // FACGE Dd,Dn,Dm
uint64x2_t vcageq_f64(float64x2_t a, float64x2_t b);                    // FACGE Vd.2D,Vn.2D,Vm.2D
uint32_t vcages_f32(float32_t a, float32_t b);                          // FACGE Sd,Sn,Sm
uint64_t vcaged_f64(float64_t a, float64_t b);                          // FACGE Dd,Dn,Dm
uint32x2_t vcale_f32(float32x2_t a, float32x2_t b);                     // FACGE Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcaleq_f32(float32x4_t a, float32x4_t b);                    // FACGE Vd.4S,Vm.4S,Vn.4S
uint64x1_t vcale_f64(float64x1_t a, float64x1_t b);                     // FACGE Dd,Dm,Dn
uint64x2_t vcaleq_f64(float64x2_t a, float64x2_t b);                    // FACGE Vd.2D,Vm.2D,Vn.2D
uint32_t vcales_f32(float32_t a, float32_t b);                          // FACGE Sd,Sm,Sn
uint64_t vcaled_f64(float64_t a, float64_t b);                          // FACGE Dd,Dm,Dn
uint32x2_t vcagt_f32(float32x2_t a, float32x2_t b);                     // FACGT Vd.2S,Vn.2S,Vm.2S
uint32x4_t vcagtq_f32(float32x4_t a, float32x4_t b);                    // FACGT Vd.4S,Vn.4S,Vm.4S
uint64x1_t vcagt_f64(float64x1_t a, float64x1_t b);                     // FACGT Dd,Dn,Dm
uint64x2_t vcagtq_f64(float64x2_t a, float64x2_t b);                    // FACGT Vd.2D,Vn.2D,Vm.2D
uint32_t vcagts_f32(float32_t a, float32_t b);                          // FACGT Sd,Sn,Sm
uint64_t vcagtd_f64(float64_t a, float64_t b);                          // FACGT Dd,Dn,Dm
uint32x2_t vcalt_f32(float32x2_t a, float32x2_t b);                     // FACGT Vd.2S,Vm.2S,Vn.2S
uint32x4_t vcaltq_f32(float32x4_t a, float32x4_t b);                    // FACGT Vd.4S,Vm.4S,Vn.4S
uint64x1_t vcalt_f64(float64x1_t a, float64x1_t b);                     // FACGT Dd,Dm,Dn
uint64x2_t vcaltq_f64(float64x2_t a, float64x2_t b);                    // FACGT Vd.2D,Vn.2D,Vm.2D
uint32_t vcalts_f32(float32_t a, float32_t b);                          // FACGT Sd,Sm,Sn
uint64_t vcaltd_f64(float64_t a, float64_t b);                          // FACGT Dd,Dm,Dn
uint8x8_t vtst_s8(int8x8_t a, int8x8_t b);                              // CMTST Vd.8B,Vn.8B,Vm.8B
uint8x16_t vtstq_s8(int8x16_t a, int8x16_t b);                        // CMTST Vd.16B,Vn.16B,Vm.16B
uint16x4_t vtst_s16(int16x4_t a, int16x4_t b);                        // CMTST Vd.4H,Vn.4H,Vm.4H
uint16x8_t vtstq_s16(int16x8_t a, int16x8_t b);                       // CMTST Vd.8H,Vn.8H,Vm.8H
uint32x2_t vtst_s32(int32x2_t a, int32x2_t b);                        // CMTST Vd.2S,Vn.2S,Vm.2S
uint32x4_t vtstq_s32(int32x4_t a, int32x4_t b);                       // CMTST Vd.4S,Vn.4S,Vm.4S
uint8x8_t vtst_u8(uint8x8_t a, uint8x8_t b);                          // CMTST Vd.8B,Vn.8B,Vm.8B
uint8x16_t vtstq_u8(uint8x16_t a, uint8x16_t b);                      // CMTST Vd.16B,Vn.16B,Vm.16B
uint16x4_t vtst_u16(uint16x4_t a, uint16x4_t b);                      // CMTST Vd.4H,Vn.4H,Vm.4H
uint16x8_t vtstq_u16(uint16x8_t a, uint16x8_t b);                     // CMTST Vd.8H,Vn.8H,Vm.8H
uint32x2_t vtst_u32(uint32x2_t a, uint32x2_t b);                      // CMTST Vd.2S,Vn.2S,Vm.2S
uint32x4_t vtstq_u32(uint32x4_t a, uint32x4_t b);                     // CMTST Vd.4S,Vn.4S,Vm.4S
uint8x8_t vtst_p8(poly8x8_t a, poly8x8_t b);                          // CMTST Vd.8B,Vn.8B,Vm.8B
uint8x16_t vtstq_p8(poly8x16_t a, poly8x16_t b);                      // CMTST Vd.16B,Vn.16B,Vm.16B
uint64x1_t vtst_s64(int64x1_t a, int64x1_t b);                        // CMTST Dd,Dn,Dm
uint64x2_t vtstq_s64(int64x2_t a, int64x2_t b);                       // CMTST Vd.2D,Vn.2D,Vm.2D
uint64x1_t vtst_u64(uint64x1_t a, uint64x1_t b);                      // CMTST Dd,Dn,Dm
uint64x2_t vtstq_u64(uint64x2_t a, uint64x2_t b);                     // CMTST Vd.2D,Vn.2D,Vm.2D
uint64x1_t vtst_p64(poly64x1_t a, poly64x1_t b);                      // CMTST Dd,Dn,Dm
uint64x2_t vtstq_p64(poly64x2_t a, poly64x2_t b);                     // CMTST Vd.2D,Vn.2D,Vm.2D
uint64_t vtstd_s64(int64_t a, int64_t b);                             // CMTST Dd,Dn,Dm
uint64_t vtstd_u64(uint64_t a, uint64_t b);                           // CMTST Dd,Dn,Dm
int8x8_t vabd_s8(int8x8_t a, int8x8_t b);                             // SABD Vd.8B,Vn.8B,Vm.8B
int8x16_t vabdq_s8(int8x16_t a, int8x16_t b);                         // SABD Vd.16B,Vn.16B,Vm.16B
int16x4_t vabd_s16(int16x4_t a, int16x4_t b);                         // SABD Vd.4H,Vn.4H,Vm.4H
int16x8_t vabdq_s16(int16x8_t a, int16x8_t b);                        // SABD Vd.8H,Vn.8H,Vm.8H
int32x2_t vabd_s32(int32x2_t a, int32x2_t b);                         // SABD Vd.2S,Vn.2S,Vm.2S
int32x4_t vabdq_s32(int32x4_t a, int32x4_t b);                        // SABD Vd.4S,Vn.4S,Vm.4S
uint8x8_t vabd_u8(uint8x8_t a, uint8x8_t b);                          // UABD Vd.8B,Vn.8B,Vm.8B
uint8x16_t vabdq_u8(uint8x16_t a, uint8x16_t b);                      // UABD Vd.16B,Vn.16B,Vm.16B
uint16x4_t vabd_u16(uint16x4_t a, uint16x4_t b);                      // UABD Vd.4H,Vn.4H,Vm.4H
uint16x8_t vabdq_u16(uint16x8_t a, uint16x8_t b);                     // UABD Vd.8H,Vn.8H,Vm.8H
uint32x2_t vabd_u32(uint32x2_t a, uint32x2_t b);                      // UABD Vd.2S,Vn.2S,Vm.2S
uint32x4_t vabdq_u32(uint32x4_t a, uint32x4_t b);                     // UABD Vd.4S,Vn.4S,Vm.4S
float32x2_t vabd_f32(float32x2_t a, float32x2_t b);                   // FABD Vd.2S,Vn.2S,Vm.2S
float32x4_t vabdq_f32(float32x4_t a, float32x4_t b);                  // FABD Vd.4S,Vn.4S,Vm.4S
float64x1_t vabd_f64(float64x1_t a, float64x1_t b);                   // FABD Dd,Dn,Dm
float64x2_t vabdq_f64(float64x2_t a, float64x2_t b);                  // FABD Vd.2D,Vn.2D,Vm.2D
float32_t vabds_f32(float32_t a, float32_t b);                        // FABD Sd,Sn,Sm
float64_t vabdd_f64(float64_t a, float64_t b);                        // FABD Dd,Dn,Dm
int16x8_t vabdl_s8(int8x8_t a, int8x8_t b);                           // SABDL Vd.8H,Vn.8B,Vm.8B
int32x4_t vabdl_s16(int16x4_t a, int16x4_t b);                        // SABDL Vd.4S,Vn.4H,Vm.4H
int64x2_t vabdl_s32(int32x2_t a, int32x2_t b);                        // SABDL Vd.2D,Vn.2S,Vm.2S
uint16x8_t vabdl_u8(uint8x8_t a, uint8x8_t b);                        // UABDL Vd.8H,Vn.8B,Vm.8B
uint32x4_t vabdl_u16(uint16x4_t a, uint16x4_t b);                     // UABDL Vd.4S,Vn.4H,Vm.4H
uint64x2_t vabdl_u32(uint32x2_t a, uint32x2_t b);                     // UABDL Vd.2D,Vn.2S,Vm.2S
int16x8_t vabdl_high_s8(int8x16_t a, int8x16_t b);                    // SABDL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vabdl_high_s16(int16x8_t a, int16x8_t b);                   // SABDL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vabdl_high_s32(int32x4_t a, int32x4_t b);                   // SABDL2 Vd.2D,Vn.4S,Vm.4S
uint16x8_t vabdl_high_u8(uint8x16_t a, uint8x16_t b);                 // UABDL2 Vd.8H,Vn.16B,Vm.16B
uint32x4_t vabdl_high_u16(uint16x8_t a, uint16x8_t b);                // UABDL2 Vd.4S,Vn.8H,Vm.8H
uint64x2_t vabdl_high_u32(uint32x4_t a, uint32x4_t b);                // UABDL2 Vd.2D,Vn.4S,Vm.4S
int8x8_t vaba_s8(int8x8_t a, int8x8_t b, int8x8_t c);                 // SABA Vd.8B,Vn.8B,Vm.8B
int8x16_t vabaq_s8(int8x16_t a, int8x16_t b, int8x16_t c);            // SABA Vd.16B,Vn.16B,Vm.16B
int16x4_t vaba_s16(int16x4_t a, int16x4_t b, int16x4_t c);            // SABA Vd.4H,Vn.4H,Vm.4H
int16x8_t vabaq_s16(int16x8_t a, int16x8_t b, int16x8_t c);           // SABA Vd.8H,Vn.8H,Vm.8H
int32x2_t vaba_s32(int32x2_t a, int32x2_t b, int32x2_t c);            // SABA Vd.2S,Vn.2S,Vm.2S
int32x4_t vabaq_s32(int32x4_t a, int32x4_t b, int32x4_t c);           // SABA Vd.4S,Vn.4S,Vm.4S
uint8x8_t vaba_u8(uint8x8_t a, uint8x8_t b, uint8x8_t c);             // UABA Vd.8B,Vn.8B,Vm.8B
uint8x16_t vabaq_u8(uint8x16_t a, uint8x16_t b, uint8x16_t c);        // UABA Vd.16B,Vn.16B,Vm.16B
uint16x4_t vaba_u16(uint16x4_t a, uint16x4_t b, uint16x4_t c);        // UABA Vd.4H,Vn.4H,Vm.4H
uint16x8_t vabaq_u16(uint16x8_t a, uint16x8_t b, uint16x8_t c);       // UABA Vd.8H,Vn.8H,Vm.8H
uint32x2_t vaba_u32(uint32x2_t a, uint32x2_t b, uint32x2_t c);        // UABA Vd.2S,Vn.2S,Vm.2S
uint32x4_t vabaq_u32(uint32x4_t a, uint32x4_t b, uint32x4_t c);       // UABA Vd.4S,Vn.4S,Vm.4S
int16x8_t vabal_s8(int16x8_t a, int8x8_t b, int8x8_t c);              // SABAL Vd.8H,Vn.8B,Vm.8B
int32x4_t vabal_s16(int32x4_t a, int16x4_t b, int16x4_t c);           // SABAL Vd.4S,Vn.4H,Vm.4H
int64x2_t vabal_s32(int64x2_t a, int32x2_t b, int32x2_t c);           // SABAL Vd.2D,Vn.2S,Vm.2S
uint16x8_t vabal_u8(uint16x8_t a, uint8x8_t b, uint8x8_t c);          // UABAL Vd.8H,Vn.8B,Vm.8B
uint32x4_t vabal_u16(uint32x4_t a, uint16x4_t b, uint16x4_t c);       // UABAL Vd.4S,Vn.4H,Vm.4H
uint64x2_t vabal_u32(uint64x2_t a, uint32x2_t b, uint32x2_t c);       // UABAL Vd.2D,Vn.2S,Vm.2S
int16x8_t vabal_high_s8(int16x8_t a, int8x16_t b, int8x16_t c);       // SABAL2 Vd.8H,Vn.16B,Vm.16B
int32x4_t vabal_high_s16(int32x4_t a, int16x8_t b, int16x8_t c);      // SABAL2 Vd.4S,Vn.8H,Vm.8H
int64x2_t vabal_high_s32(int64x2_t a, int32x4_t b, int32x4_t c);      // SABAL2 Vd.2D,Vn.4S,Vm.4S
uint16x8_t vabal_high_u8(uint16x8_t a, uint8x16_t b, uint8x16_t c);   // UABAL2 Vd.8H,Vn.16B,Vm.16B
uint32x4_t vabal_high_u16(uint32x4_t a, uint16x8_t b, uint16x8_t c);  // UABAL2 Vd.4S,Vn.8H,Vm.8H
uint64x2_t vabal_high_u32(uint64x2_t a, uint32x4_t b, uint32x4_t c);  // UABAL2 Vd.2D,Vn.4S,Vm.4S
int8x8_t vmax_s8(int8x8_t a, int8x8_t b);                             // SMAX Vd.8B,Vn.8B,Vm.8B
int8x16_t vmaxq_s8(int8x16_t a, int8x16_t b);                         // SMAX Vd.16B,Vn.16B,Vm.16B
int16x4_t vmax_s16(int16x4_t a, int16x4_t b);                         // SMAX Vd.4H,Vn.4H,Vm.4H
int16x8_t vmaxq_s16(int16x8_t a, int16x8_t b);                        // SMAX Vd.8H,Vn.8H,Vm.8H
int32x2_t vmax_s32(int32x2_t a, int32x2_t b);                         // SMAX Vd.2S,Vn.2S,Vm.2S
int32x4_t vmaxq_s32(int32x4_t a, int32x4_t b);                        // SMAX Vd.4S,Vn.4S,Vm.4S
uint8x8_t vmax_u8(uint8x8_t a, uint8x8_t b);                          // UMAX Vd.8B,Vn.8B,Vm.8B
uint8x16_t vmaxq_u8(uint8x16_t a, uint8x16_t b);                      // UMAX Vd.16B,Vn.16B,Vm.16B
uint16x4_t vmax_u16(uint16x4_t a, uint16x4_t b);                      // UMAX Vd.4H,Vn.4H,Vm.4H
uint16x8_t vmaxq_u16(uint16x8_t a, uint16x8_t b);                     // UMAX Vd.8H,Vn.8H,Vm.8H
uint32x2_t vmax_u32(uint32x2_t a, uint32x2_t b);                      // UMAX Vd.2S,Vn.2S,Vm.2S
uint32x4_t vmaxq_u32(uint32x4_t a, uint32x4_t b);                     // UMAX Vd.4S,Vn.4S,Vm.4S
float32x2_t vmax_f32(float32x2_t a, float32x2_t b);                   // FMAX Vd.2S,Vn.2S,Vm.2S
float32x4_t vmaxq_f32(float32x4_t a, float32x4_t b);                  // FMAX Vd.4S,Vn.4S,Vm.4S
float64x1_t vmax_f64(float64x1_t a, float64x1_t b);                   // FMAX Dd,Dn,Dm
float64x2_t vmaxq_f64(float64x2_t a, float64x2_t b);                  // FMAX Vd.2D,Vn.2D,Vm.2D
int8x8_t vmin_s8(int8x8_t a, int8x8_t b);                             // SMIN Vd.8B,Vn.8B,Vm.8B
int8x16_t vminq_s8(int8x16_t a, int8x16_t b);                         // SMIN Vd.16B,Vn.16B,Vm.16B
int16x4_t vmin_s16(int16x4_t a, int16x4_t b);                         // SMIN Vd.4H,Vn.4H,Vm.4H
int16x8_t vminq_s16(int16x8_t a, int16x8_t b);                        // SMIN Vd.8H,Vn.8H,Vm.8H
int32x2_t vmin_s32(int32x2_t a, int32x2_t b);                         // SMIN Vd.2S,Vn.2S,Vm.2S
int32x4_t vminq_s32(int32x4_t a, int32x4_t b);                        // SMIN Vd.4S,Vn.4S,Vm.4S
uint8x8_t vmin_u8(uint8x8_t a, uint8x8_t b);                          // UMIN Vd.8B,Vn.8B,Vm.8B
uint8x16_t vminq_u8(uint8x16_t a, uint8x16_t b);                      // UMIN Vd.16B,Vn.16B,Vm.16B
uint16x4_t vmin_u16(uint16x4_t a, uint16x4_t b);                      // UMIN Vd.4H,Vn.4H,Vm.4H
uint16x8_t vminq_u16(uint16x8_t a, uint16x8_t b);                     // UMIN Vd.8H,Vn.8H,Vm.8H
uint32x2_t vmin_u32(uint32x2_t a, uint32x2_t b);                      // UMIN Vd.2S,Vn.2S,Vm.2S
uint32x4_t vminq_u32(uint32x4_t a, uint32x4_t b);                     // UMIN Vd.4S,Vn.4S,Vm.4S
float32x2_t vmin_f32(float32x2_t a, float32x2_t b);                   // FMIN Vd.2S,Vn.2S,Vm.2S
float32x4_t vminq_f32(float32x4_t a, float32x4_t b);                  // FMIN Vd.4S,Vn.4S,Vm.4S
float64x1_t vmin_f64(float64x1_t a, float64x1_t b);                   // FMIN Dd,Dn,Dm
float64x2_t vminq_f64(float64x2_t a, float64x2_t b);                  // FMIN Vd.2D,Vn.2D,Vm.2D
float32x2_t vmaxnm_f32(float32x2_t a, float32x2_t b);                 // FMAXNM Vd.2S,Vn.2S,Vm.2S
float32x4_t vmaxnmq_f32(float32x4_t a, float32x4_t b);                // FMAXNM Vd.4S,Vn.4S,Vm.4S
float64x1_t vmaxnm_f64(float64x1_t a, float64x1_t b);                 // FMAXNM Dd,Dn,Dm
float64x2_t vmaxnmq_f64(float64x2_t a, float64x2_t b);                // FMAXNM Vd.2D,Vn.2D,Vm.2D
float32x2_t vminnm_f32(float32x2_t a, float32x2_t b);                 // FMINNM Vd.2S,Vn.2S,Vm.2S
float32x4_t vminnmq_f32(float32x4_t a, float32x4_t b);                // FMINNM Vd.4S,Vn.4S,Vm.4S
float64x1_t vminnm_f64(float64x1_t a, float64x1_t b);                 // FMINNM Dd,Dn,Dm
float64x2_t vminnmq_f64(float64x2_t a, float64x2_t b);                // FMINNM Vd.2D,Vn.2D,Vm.2D
int8x8_t vshl_s8(int8x8_t a, int8x8_t b);                             // SSHL Vd.8B,Vn.8B,Vm.8B
int8x16_t vshlq_s8(int8x16_t a, int8x16_t b);                         // SSHL Vd.16B,Vn.16B,Vm.16B
int16x4_t vshl_s16(int16x4_t a, int16x4_t b);                         // SSHL Vd.4H,Vn.4H,Vm.4H
int16x8_t vshlq_s16(int16x8_t a, int16x8_t b);                        // SSHL Vd.8H,Vn.8H,Vm.8H
int32x2_t vshl_s32(int32x2_t a, int32x2_t b);                         // SSHL Vd.2S,Vn.2S,Vm.2S
int32x4_t vshlq_s32(int32x4_t a, int32x4_t b);                        // SSHL Vd.4S,Vn.4S,Vm.4S
int64x1_t vshl_s64(int64x1_t a, int64x1_t b);                         // SSHL Dd,Dn,Dm
int64x2_t vshlq_s64(int64x2_t a, int64x2_t b);                        // SSHL Vd.2D,Vn.2D,Vm.2D
uint8x8_t vshl_u8(uint8x8_t a, int8x8_t b);                           // USHL Vd.8B,Vn.8B,Vm.8B
uint8x16_t vshlq_u8(uint8x16_t a, int8x16_t b);                       // USHL Vd.16B,Vn.16B,Vm.16B
uint16x4_t vshl_u16(uint16x4_t a, int16x4_t b);                       // USHL Vd.4H,Vn.4H,Vm.4H
uint16x8_t vshlq_u16(uint16x8_t a, int16x8_t b);                      // USHL Vd.8H,Vn.8H,Vm.8H
uint32x2_t vshl_u32(uint32x2_t a, int32x2_t b);                       // USHL Vd.2S,Vn.2S,Vm.2S
uint32x4_t vshlq_u32(uint32x4_t a, int32x4_t b);                      // USHL Vd.4S,Vn.4S,Vm.4S
uint64x1_t vshl_u64(uint64x1_t a, int64x1_t b);                       // USHL Dd,Dn,Dm
uint64x2_t vshlq_u64(uint64x2_t a, int64x2_t b);                      // USHL Vd.2D,Vn.2D,Vm.2D
int64_t vshld_s64(int64_t a, int64_t b);                              // SSHL Dd,Dn,Dm
uint64_t vshld_u64(uint64_t a, int64_t b);                            // USHL Dd,Dn,Dm
int8x8_t vqshl_s8(int8x8_t a, int8x8_t b);                            // SQSHL Vd.8B,Vn.8B,Vm.8B
int8x16_t vqshlq_s8(int8x16_t a, int8x16_t b);                        // SQSHL Vd.16B,Vn.16B,Vm.16B
int16x4_t vqshl_s16(int16x4_t a, int16x4_t b);                        // SQSHL Vd.4H,Vn.4H,Vm.4H
int16x8_t vqshlq_s16(int16x8_t a, int16x8_t b);                       // SQSHL Vd.8H,Vn.8H,Vm.8H
int32x2_t vqshl_s32(int32x2_t a, int32x2_t b);                        // SQSHL Vd.2S,Vn.2S,Vm.2S
int32x4_t vqshlq_s32(int32x4_t a, int32x4_t b);                       // SQSHL Vd.4S,Vn.4S,Vm.4S
int64x1_t vqshl_s64(int64x1_t a, int64x1_t b);                        // SQSHL Dd,Dn,Dm
int64x2_t vqshlq_s64(int64x2_t a, int64x2_t b);                       // SQSHL Vd.2D,Vn.2D,Vm.2D
uint8x8_t vqshl_u8(uint8x8_t a, int8x8_t b);                          // UQSHL Vd.8B,Vn.8B,Vm.8B
uint8x16_t vqshlq_u8(uint8x16_t a, int8x16_t b);                      // UQSHL Vd.16B,Vn.16B,Vm.16B
uint16x4_t vqshl_u16(uint16x4_t a, int16x4_t b);                      // UQSHL Vd.4H,Vn.4H,Vm.4H
uint16x8_t vqshlq_u16(uint16x8_t a, int16x8_t b);                     // UQSHL Vd.8H,Vn.8H,Vm.8H
uint32x2_t vqshl_u32(uint32x2_t a, int32x2_t b);                      // UQSHL Vd.2S,Vn.2S,Vm.2S
uint32x4_t vqshlq_u32(uint32x4_t a, int32x4_t b);                     // UQSHL Vd.4S,Vn.4S,Vm.4S
uint64x1_t vqshl_u64(uint64x1_t a, int64x1_t b);                      // UQSHL Dd,Dn,Dm
uint64x2_t vqshlq_u64(uint64x2_t a, int64x2_t b);                     // UQSHL Vd.2D,Vn.2D,Vm.2D
int8_t vqshlb_s8(int8_t a, int8_t b);                                 // SQSHL Bd,Bn,Bm
int16_t vqshlh_s16(int16_t a, int16_t b);                             // SQSHL Hd,Hn,Hm
int32_t vqshls_s32(int32_t a, int32_t b);                             // SQSHL Sd,Sn,Sm
int64_t vqshld_s64(int64_t a, int64_t b);                             // SQSHL Dd,Dn,Dm
uint8_t vqshlb_u8(uint8_t a, int8_t b);                               // UQSHL Bd,Bn,Bm
uint16_t vqshlh_u16(uint16_t a, int16_t b);                           // UQSHL Hd,Hn,Hm
uint32_t vqshls_u32(uint32_t a, int32_t b);                           // UQSHL Sd,Sn,Sm
uint64_t vqshld_u64(uint64_t a, int64_t b);                           // UQSHL Dd,Dn,Dm
int8x8_t vrshl_s8(int8x8_t a, int8x8_t b);                            // SRSHL Vd.8B,Vn.8B,Vm.8B
int8x16_t vrshlq_s8(int8x16_t a, int8x16_t b);                        // SRSHL Vd.16B,Vn.16B,Vm.16B
int16x4_t vrshl_s16(int16x4_t a, int16x4_t b);                        // SRSHL Vd.4H,Vn.4H,Vm.4H
int16x8_t vrshlq_s16(int16x8_t a, int16x8_t b);                       // SRSHL Vd.8H,Vn.8H,Vm.8H
int32x2_t vrshl_s32(int32x2_t a, int32x2_t b);                        // SRSHL Vd.2S,Vn.2S,Vm.2S
int32x4_t vrshlq_s32(int32x4_t a, int32x4_t b);                       // SRSHL Vd.4S,Vn.4S,Vm.4S
int64x1_t vrshl_s64(int64x1_t a, int64x1_t b);                        // SRSHL Dd,Dn,Dm
int64x2_t vrshlq_s64(int64x2_t a, int64x2_t b);                       // SRSHL Vd.2D,Vn.2D,Vm.2D
uint8x8_t vrshl_u8(uint8x8_t a, int8x8_t b);                          // URSHL Vd.8B,Vn.8B,Vm.8B
uint8x16_t vrshlq_u8(uint8x16_t a, int8x16_t b);                      // URSHL Vd.16B,Vn.16B,Vm.16B
uint16x4_t vrshl_u16(uint16x4_t a, int16x4_t b);                      // URSHL Vd.4H,Vn.4H,Vm.4H
uint16x8_t vrshlq_u16(uint16x8_t a, int16x8_t b);                     // URSHL Vd.8H,Vn.8H,Vm.8H
uint32x2_t vrshl_u32(uint32x2_t a, int32x2_t b);                      // URSHL Vd.2S,Vn.2S,Vm.2S
uint32x4_t vrshlq_u32(uint32x4_t a, int32x4_t b);                     // URSHL Vd.4S,Vn.4S,Vm.4S
uint64x1_t vrshl_u64(uint64x1_t a, int64x1_t b);                      // URSHL Dd,Dn,Dm
uint64x2_t vrshlq_u64(uint64x2_t a, int64x2_t b);                     // URSHL Vd.2D,Vn.2D,Vm.2D
int64_t vrshld_s64(int64_t a, int64_t b);                             // SRSHL Dd,Dn,Dm
uint64_t vrshld_u64(uint64_t a, int64_t b);                           // URSHL Dd,Dn,Dm
int8x8_t vqrshl_s8(int8x8_t a, int8x8_t b);                           // SQRSHL Vd.8B,Vn.8B,Vm.8B
int8x16_t vqrshlq_s8(int8x16_t a, int8x16_t b);                       // SQRSHL Vd.16B,Vn.16B,Vm.16B
int16x4_t vqrshl_s16(int16x4_t a, int16x4_t b);                       // SQRSHL Vd.4H,Vn.4H,Vm.4H
int16x8_t vqrshlq_s16(int16x8_t a, int16x8_t b);                      // SQRSHL Vd.8H,Vn.8H,Vm.8H
int32x2_t vqrshl_s32(int32x2_t a, int32x2_t b);                       // SQRSHL Vd.2S,Vn.2S,Vm.2S
int32x4_t vqrshlq_s32(int32x4_t a, int32x4_t b);                      // SQRSHL Vd.4S,Vn.4S,Vm.4S
int64x1_t vqrshl_s64(int64x1_t a, int64x1_t b);                       // SQRSHL Dd,Dn,Dm
int64x2_t vqrshlq_s64(int64x2_t a, int64x2_t b);                      // SQRSHL Vd.2D,Vn.2D,Vm.2D
uint8x8_t vqrshl_u8(uint8x8_t a, int8x8_t b);                         // UQRSHL Vd.8B,Vn.8B,Vm.8B
uint8x16_t vqrshlq_u8(uint8x16_t a, int8x16_t b);                     // UQRSHL Vd.16B,Vn.16B,Vm.16B
uint16x4_t vqrshl_u16(uint16x4_t a, int16x4_t b);                     // UQRSHL Vd.4H,Vn.4H,Vm.4H
uint16x8_t vqrshlq_u16(uint16x8_t a, int16x8_t b);                    // UQRSHL Vd.8H,Vn.8H,Vm.8H
uint32x2_t vqrshl_u32(uint32x2_t a, int32x2_t b);                     // UQRSHL Vd.2S,Vn.2S,Vm.2S
uint32x4_t vqrshlq_u32(uint32x4_t a, int32x4_t b);                    // UQRSHL Vd.4S,Vn.4S,Vm.4S
uint64x1_t vqrshl_u64(uint64x1_t a, int64x1_t b);                     // UQRSHL Dd,Dn,Dm
uint64x2_t vqrshlq_u64(uint64x2_t a, int64x2_t b);                    // UQRSHL Vd.2D,Vn.2D,Vm.2D
int8_t vqrshlb_s8(int8_t a, int8_t b);                                // SQRSHL Bd,Bn,Bm
int16_t vqrshlh_s16(int16_t a, int16_t b);                            // SQRSHL Hd,Hn,Hm
int32_t vqrshls_s32(int32_t a, int32_t b);                            // SQRSHL Sd,Sn,Sm
int64_t vqrshld_s64(int64_t a, int64_t b);                            // SQRSHL Dd,Dn,Dm
uint8_t vqrshlb_u8(uint8_t a, int8_t b);                              // UQRSHL Bd,Bn,Bm
uint16_t vqrshlh_u16(uint16_t a, int16_t b);                          // UQRSHL Hd,Hn,Hm
uint32_t vqrshls_u32(uint32_t a, int32_t b);                          // UQRSHL Sd,Sn,Sm
uint64_t vqrshld_u64(uint64_t a, int64_t b);                          // UQRSHL Dd,Dn,Dm
int8x8_t vshr_n_s8(int8x8_t a, const int n);                          // SSHR Vd.8B,Vn.8B,#n
int8x16_t vshrq_n_s8(int8x16_t a, const int n);                       // SSHR Vd.16B,Vn.16B,#n
int16x4_t vshr_n_s16(int16x4_t a, const int n);                       // SSHR Vd.4H,Vn.4H,#n
int16x8_t vshrq_n_s16(int16x8_t a, const int n);                      // SSHR Vd.8H,Vn.8H,#n
int32x2_t vshr_n_s32(int32x2_t a, const int n);                       // SSHR Vd.2S,Vn.2S,#n
int32x4_t vshrq_n_s32(int32x4_t a, const int n);                      // SSHR Vd.4S,Vn.4S,#n
int64x1_t vshr_n_s64(int64x1_t a, const int n);                       // SSHR Dd,Dn,#n
int64x2_t vshrq_n_s64(int64x2_t a, const int n);                      // SSHR Vd.2D,Vn.2D,#n
uint8x8_t vshr_n_u8(uint8x8_t a, const int n);                        // USHR Vd.8B,Vn.8B,#n
uint8x16_t vshrq_n_u8(uint8x16_t a, const int n);                     // USHR Vd.16B,Vn.16B,#n
uint16x4_t vshr_n_u16(uint16x4_t a, const int n);                     // USHR Vd.4H,Vn.4H,#n
uint16x8_t vshrq_n_u16(uint16x8_t a, const int n);                    // USHR Vd.8H,Vn.8H,#n
uint32x2_t vshr_n_u32(uint32x2_t a, const int n);                     // USHR Vd.2S,Vn.2S,#n
uint32x4_t vshrq_n_u32(uint32x4_t a, const int n);                    // USHR Vd.4S,Vn.4S,#n
uint64x1_t vshr_n_u64(uint64x1_t a, const int n);                     // USHR Dd,Dn,#n
uint64x2_t vshrq_n_u64(uint64x2_t a, const int n);                    // USHR Vd.2D,Vn.2D,#n
int64_t vshrd_n_s64(int64_t a, const int n);                          // SSHR Dd,Dn,#n
uint64_t vshrd_n_u64(uint64_t a, const int n);                        // USHR Dd,Dn,#n
int8x8_t vshl_n_s8(int8x8_t a, const int n);                          // SHL Vd.8B,Vn.8B,#n
int8x16_t vshlq_n_s8(int8x16_t a, const int n);                       // SHL Vd.16B,Vn.16B,#n
int16x4_t vshl_n_s16(int16x4_t a, const int n);                       // SHL Vd.4H,Vn.4H,#n
int16x8_t vshlq_n_s16(int16x8_t a, const int n);                      // SHL Vd.8H,Vn.8H,#n
int32x2_t vshl_n_s32(int32x2_t a, const int n);                       // SHL Vd.2S,Vn.2S,#n
int32x4_t vshlq_n_s32(int32x4_t a, const int n);                      // SHL Vd.4S,Vn.4S,#n
int64x1_t vshl_n_s64(int64x1_t a, const int n);                       // SHL Dd,Dn,#n
int64x2_t vshlq_n_s64(int64x2_t a, const int n);                      // SHL Vd.2D,Vn.2D,#n
uint8x8_t vshl_n_u8(uint8x8_t a, const int n);                        // SHL Vd.8B,Vn.8B,#n
uint8x16_t vshlq_n_u8(uint8x16_t a, const int n);                     // SHL Vd.16B,Vn.16B,#n
uint16x4_t vshl_n_u16(uint16x4_t a, const int n);                     // SHL Vd.4H,Vn.4H,#n
uint16x8_t vshlq_n_u16(uint16x8_t a, const int n);                    // SHL Vd.8H,Vn.8H,#n
uint32x2_t vshl_n_u32(uint32x2_t a, const int n);                     // SHL Vd.2S,Vn.2S,#n
uint32x4_t vshlq_n_u32(uint32x4_t a, const int n);                    // SHL Vd.4S,Vn.4S,#n
uint64x1_t vshl_n_u64(uint64x1_t a, const int n);                     // SHL Dd,Dn,#n
uint64x2_t vshlq_n_u64(uint64x2_t a, const int n);                    // SHL Vd.2D,Vn.2D,#n
int64_t vshld_n_s64(int64_t a, const int n);                          // SHL Dd,Dn,#n
uint64_t vshld_n_u64(uint64_t a, const int n);                        // SHL Dd,Dn,#n
int8x8_t vrshr_n_s8(int8x8_t a, const int n);                         // SRSHR Vd.8B,Vn.8B,#n
int8x16_t vrshrq_n_s8(int8x16_t a, const int n);                      // SRSHR Vd.16B,Vn.16B,#n
int16x4_t vrshr_n_s16(int16x4_t a, const int n);                      // SRSHR Vd.4H,Vn.4H,#n
int16x8_t vrshrq_n_s16(int16x8_t a, const int n);                     // SRSHR Vd.8H,Vn.8H,#n
int32x2_t vrshr_n_s32(int32x2_t a, const int n);                      // SRSHR Vd.2S,Vn.2S,#n
int32x4_t vrshrq_n_s32(int32x4_t a, const int n);                     // SRSHR Vd.4S,Vn.4S,#n
int64x1_t vrshr_n_s64(int64x1_t a, const int n);                      // SRSHR Dd,Dn,#n
int64x2_t vrshrq_n_s64(int64x2_t a, const int n);                     // SRSHR Vd.2D,Vn.2D,#n
uint8x8_t vrshr_n_u8(uint8x8_t a, const int n);                       // URSHR Vd.8B,Vn.8B,#n
uint8x16_t vrshrq_n_u8(uint8x16_t a, const int n);                    // URSHR Vd.16B,Vn.16B,#n
uint16x4_t vrshr_n_u16(uint16x4_t a, const int n);                    // URSHR Vd.4H,Vn.4H,#n
uint16x8_t vrshrq_n_u16(uint16x8_t a, const int n);                   // URSHR Vd.8H,Vn.8H,#n
uint32x2_t vrshr_n_u32(uint32x2_t a, const int n);                    // URSHR Vd.2S,Vn.2S,#n
uint32x4_t vrshrq_n_u32(uint32x4_t a, const int n);                   // URSHR Vd.4S,Vn.4S,#n
uint64x1_t vrshr_n_u64(uint64x1_t a, const int n);                    // URSHR Dd,Dn,#n
uint64x2_t vrshrq_n_u64(uint64x2_t a, const int n);                   // URSHR Vd.2D,Vn.2D,#n
int64_t vrshrd_n_s64(int64_t a, const int n);                         // SRSHR Dd,Dn,#n
uint64_t vrshrd_n_u64(uint64_t a, const int n);                       // URSHR Dd,Dn,#n
int8x8_t vsra_n_s8(int8x8_t a, int8x8_t b, const int n);              // SSRA Vd.8B,Vn.8B,#n
int8x16_t vsraq_n_s8(int8x16_t a, int8x16_t b, const int n);          // SSRA Vd.16B,Vn.16B,#n
int16x4_t vsra_n_s16(int16x4_t a, int16x4_t b, const int n);          // SSRA Vd.4H,Vn.4H,#n
int16x8_t vsraq_n_s16(int16x8_t a, int16x8_t b, const int n);         // SSRA Vd.8H,Vn.8H,#n
int32x2_t vsra_n_s32(int32x2_t a, int32x2_t b, const int n);          // SSRA Vd.2S,Vn.2S,#n
int32x4_t vsraq_n_s32(int32x4_t a, int32x4_t b, const int n);         // SSRA Vd.4S,Vn.4S,#n
int64x1_t vsra_n_s64(int64x1_t a, int64x1_t b, const int n);          // SSRA Dd,Dn,#n
int64x2_t vsraq_n_s64(int64x2_t a, int64x2_t b, const int n);         // SSRA Vd.2D,Vn.2D,#n
uint8x8_t vsra_n_u8(uint8x8_t a, uint8x8_t b, const int n);           // USRA Vd.8B,Vn.8B,#n
uint8x16_t vsraq_n_u8(uint8x16_t a, uint8x16_t b, const int n);       // USRA Vd.16B,Vn.16B,#n
uint16x4_t vsra_n_u16(uint16x4_t a, uint16x4_t b, const int n);       // USRA Vd.4H,Vn.4H,#n
uint16x8_t vsraq_n_u16(uint16x8_t a, uint16x8_t b, const int n);      // USRA Vd.8H,Vn.8H,#n
uint32x2_t vsra_n_u32(uint32x2_t a, uint32x2_t b, const int n);       // USRA Vd.2S,Vn.2S,#n
uint32x4_t vsraq_n_u32(uint32x4_t a, uint32x4_t b, const int n);      // USRA Vd.4S,Vn.4S,#n
uint64x1_t vsra_n_u64(uint64x1_t a, uint64x1_t b, const int n);       // USRA Dd,Dn,#n
uint64x2_t vsraq_n_u64(uint64x2_t a, uint64x2_t b, const int n);      // USRA Vd.2D,Vn.2D,#n
int64_t vsrad_n_s64(int64_t a, int64_t b, const int n);               // SSRA Dd,Dn,#n
uint64_t vsrad_n_u64(uint64_t a, uint64_t b, const int n);            // USRA Dd,Dn,#n
int8x8_t vrsra_n_s8(int8x8_t a, int8x8_t b, const int n);             // SRSRA Vd.8B,Vn.8B,#n
int8x16_t vrsraq_n_s8(int8x16_t a, int8x16_t b, const int n);         // SRSRA Vd.16B,Vn.16B,#n
int16x4_t vrsra_n_s16(int16x4_t a, int16x4_t b, const int n);         // SRSRA Vd.4H,Vn.4H,#n
int16x8_t vrsraq_n_s16(int16x8_t a, int16x8_t b, const int n);        // SRSRA Vd.8H,Vn.8H,#n
int32x2_t vrsra_n_s32(int32x2_t a, int32x2_t b, const int n);         // SRSRA Vd.2S,Vn.2S,#n
int32x4_t vrsraq_n_s32(int32x4_t a, int32x4_t b, const int n);        // SRSRA Vd.4S,Vn.4S,#n
int64x1_t vrsra_n_s64(int64x1_t a, int64x1_t b, const int n);         // SRSRA Dd,Dn,#n
int64x2_t vrsraq_n_s64(int64x2_t a, int64x2_t b, const int n);        // SRSRA Vd.2D,Vn.2D,#n
uint8x8_t vrsra_n_u8(uint8x8_t a, uint8x8_t b, const int n);          // URSRA Vd.8B,Vn.8B,#n
uint8x16_t vrsraq_n_u8(uint8x16_t a, uint8x16_t b, const int n);      // URSRA Vd.16B,Vn.16B,#n
uint16x4_t vrsra_n_u16(uint16x4_t a, uint16x4_t b, const int n);      // URSRA Vd.4H,Vn.4H,#n
uint16x8_t vrsraq_n_u16(uint16x8_t a, uint16x8_t b, const int n);     // URSRA Vd.8H,Vn.8H,#n
uint32x2_t vrsra_n_u32(uint32x2_t a, uint32x2_t b, const int n);      // URSRA Vd.2S,Vn.2S,#n
uint32x4_t vrsraq_n_u32(uint32x4_t a, uint32x4_t b, const int n);     // URSRA Vd.4S,Vn.4S,#n
uint64x1_t vrsra_n_u64(uint64x1_t a, uint64x1_t b, const int n);      // URSRA Dd,Dn,#n
uint64x2_t vrsraq_n_u64(uint64x2_t a, uint64x2_t b, const int n);     // URSRA Vd.2D,Vn.2D,#n
int64_t vrsrad_n_s64(int64_t a, int64_t b, const int n);              // SRSRA Dd,Dn,#n
uint64_t vrsrad_n_u64(uint64_t a, uint64_t b, const int n);           // URSRA Dd,Dn,#n
int8x8_t vqshl_n_s8(int8x8_t a, const int n);                         // SQSHL Vd.8B,Vn.8B,#n
int8x16_t vqshlq_n_s8(int8x16_t a, const int n);                      // SQSHL Vd.16B,Vn.16B,#n
int16x4_t vqshl_n_s16(int16x4_t a, const int n);                      // SQSHL Vd.4H,Vn.4H,#n
int16x8_t vqshlq_n_s16(int16x8_t a, const int n);                     // SQSHL Vd.8H,Vn.8H,#n
int32x2_t vqshl_n_s32(int32x2_t a, const int n);                      // SQSHL Vd.2S,Vn.2S,#n
int32x4_t vqshlq_n_s32(int32x4_t a, const int n);                     // SQSHL Vd.4S,Vn.4S,#n
int64x1_t vqshl_n_s64(int64x1_t a, const int n);                      // SQSHL Dd,Dn,#n
int64x2_t vqshlq_n_s64(int64x2_t a, const int n);                     // SQSHL Vd.2D,Vn.2D,#n
uint8x8_t vqshl_n_u8(uint8x8_t a, const int n);                       // UQSHL Vd.8B,Vn.8B,#n
uint8x16_t vqshlq_n_u8(uint8x16_t a, const int n);                    // UQSHL Vd.16B,Vn.16B,#n
uint16x4_t vqshl_n_u16(uint16x4_t a, const int n);                    // UQSHL Vd.4H,Vn.4H,#n
uint16x8_t vqshlq_n_u16(uint16x8_t a, const int n);                   // UQSHL Vd.8H,Vn.8H,#n
uint32x2_t vqshl_n_u32(uint32x2_t a, const int n);                    // UQSHL Vd.2S,Vn.2S,#n
uint32x4_t vqshlq_n_u32(uint32x4_t a, const int n);                   // UQSHL Vd.4S,Vn.4S,#n
uint64x1_t vqshl_n_u64(uint64x1_t a, const int n);                    // UQSHL Dd,Dn,#n
uint64x2_t vqshlq_n_u64(uint64x2_t a, const int n);                   // UQSHL Vd.2D,Vn.2D,#n
int8_t vqshlb_n_s8(int8_t a, const int n);                            // SQSHL Bd,Bn,#n
int16_t vqshlh_n_s16(int16_t a, const int n);                         // SQSHL Hd,Hn,#n
int32_t vqshls_n_s32(int32_t a, const int n);                         // SQSHL Sd,Sn,#n
int64_t vqshld_n_s64(int64_t a, const int n);                         // SQSHL Dd,Dn,#n
uint8_t vqshlb_n_u8(uint8_t a, const int n);                          // UQSHL Bd,Bn,#n
uint16_t vqshlh_n_u16(uint16_t a, const int n);                       // UQSHL Hd,Hn,#n
uint32_t vqshls_n_u32(uint32_t a, const int n);                       // UQSHL Sd,Sn,#n
uint64_t vqshld_n_u64(uint64_t a, const int n);                       // UQSHL Dd,Dn,#n
uint8x8_t vqshlu_n_s8(int8x8_t a, const int n);                       // SQSHLU Vd.8B,Vn.8B,#n
uint8x16_t vqshluq_n_s8(int8x16_t a, const int n);                    // SQSHLU Vd.16B,Vn.16B,#n
uint16x4_t vqshlu_n_s16(int16x4_t a, const int n);                    // SQSHLU Vd.4H,Vn.4H,#n
uint16x8_t vqshluq_n_s16(int16x8_t a, const int n);                   // SQSHLU Vd.8H,Vn.8H,#n
uint32x2_t vqshlu_n_s32(int32x2_t a, const int n);                    // SQSHLU Vd.2S,Vn.2S,#n
uint32x4_t vqshluq_n_s32(int32x4_t a, const int n);                   // SQSHLU Vd.4S,Vn.4S,#n
uint64x1_t vqshlu_n_s64(int64x1_t a, const int n);                    // SQSHLU Dd,Dn,#n
uint64x2_t vqshluq_n_s64(int64x2_t a, const int n);                   // SQSHLU Vd.2D,Vn.2D,#n
uint8_t vqshlub_n_s8(int8_t a, const int n);                          // SQSHLU Bd,Bn,#n
uint16_t vqshluh_n_s16(int16_t a, const int n);                       // SQSHLU Hd,Hn,#n
uint32_t vqshlus_n_s32(int32_t a, const int n);                       // SQSHLU Sd,Sn,#n
uint64_t vqshlud_n_s64(int64_t a, const int n);                       // SQSHLU Dd,Dn,#n
int8x8_t vshrn_n_s16(int16x8_t a, const int n);                       // SHRN Vd.8B,Vn.8H,#n
int16x4_t vshrn_n_s32(int32x4_t a, const int n);                      // SHRN Vd.4H,Vn.4S,#n
int32x2_t vshrn_n_s64(int64x2_t a, const int n);                      // SHRN Vd.2S,Vn.2D,#n
uint8x8_t vshrn_n_u16(uint16x8_t a, const int n);                     // SHRN Vd.8B,Vn.8H,#n
uint16x4_t vshrn_n_u32(uint32x4_t a, const int n);                    // SHRN Vd.4H,Vn.4S,#n
uint32x2_t vshrn_n_u64(uint64x2_t a, const int n);                    // SHRN Vd.2S,Vn.2D,#n
int8x16_t vshrn_high_n_s16(int8x8_t r, int16x8_t a, const int n);     // SHRN2 Vd.16B,Vn.8H,#n
int16x8_t vshrn_high_n_s32(int16x4_t r, int32x4_t a, const int n);    // SHRN2 Vd.8H,Vn.4S,#n
int32x4_t vshrn_high_n_s64(int32x2_t r, int64x2_t a, const int n);    // SHRN2 Vd.4S,Vn.2D,#n
uint8x16_t vshrn_high_n_u16(uint8x8_t r, uint16x8_t a, const int n);  // SHRN2 Vd.16B,Vn.8H,#n
uint16x8_t vshrn_high_n_u32(uint16x4_t r, uint32x4_t a, const int n);   // SHRN2 Vd.8H,Vn.4S,#n
uint32x4_t vshrn_high_n_u64(uint32x2_t r, uint64x2_t a, const int n);   // SHRN2 Vd.4S,Vn.2D,#n
uint8x8_t vqshrun_n_s16(int16x8_t a, const int n);                      // SQSHRUN Vd.8B,Vn.8H,#n
uint16x4_t vqshrun_n_s32(int32x4_t a, const int n);                     // SQSHRUN Vd.4H,Vn.4S,#n
uint32x2_t vqshrun_n_s64(int64x2_t a, const int n);                     // SQSHRUN Vd.2S,Vn.2D,#n
uint8_t vqshrunh_n_s16(int16_t a, const int n);                         // SQSHRUN Bd,Hn,#n
uint16_t vqshruns_n_s32(int32_t a, const int n);                        // SQSHRUN Hd,Sn,#n
uint32_t vqshrund_n_s64(int64_t a, const int n);                        // SQSHRUN Sd,Dn,#n
uint8x16_t vqshrun_high_n_s16(uint8x8_t r, int16x8_t a, const int n);   // SQSHRUN2 Vd.16B,Vn.8H,#n
uint16x8_t vqshrun_high_n_s32(uint16x4_t r, int32x4_t a, const int n);  // SQSHRUN2 Vd.8H,Vn.4S,#n
uint32x4_t vqshrun_high_n_s64(uint32x2_t r, int64x2_t a, const int n);  // SQSHRUN2 Vd.4S,Vn.2D,#n
uint8x8_t vqrshrun_n_s16(int16x8_t a, const int n);                     // SQRSHRUN Vd.8B,Vn.8H,#n
uint16x4_t vqrshrun_n_s32(int32x4_t a, const int n);                    // SQRSHRUN Vd.4H,Vn.4S,#n
uint32x2_t vqrshrun_n_s64(int64x2_t a, const int n);                    // SQRSHRUN Vd.2S,Vn.2D,#n
uint8_t vqrshrunh_n_s16(int16_t a, const int n);                        // SQRSHRUN Bd,Hn,#n
uint16_t vqrshruns_n_s32(int32_t a, const int n);                       // SQRSHRUN Hd,Sn,#n
uint32_t vqrshrund_n_s64(int64_t a, const int n);                       // SQRSHRUN Sd,Dn,#n
uint8x16_t vqrshrun_high_n_s16(uint8x8_t r, int16x8_t a, const int n);  // SQRSHRUN2 Vd.16B,Vn.8H,#n
uint16x8_t vqrshrun_high_n_s32(uint16x4_t r, int32x4_t a, const int n);  // SQRSHRUN2 Vd.8H,Vn.4S,#n
uint32x4_t vqrshrun_high_n_s64(uint32x2_t r, int64x2_t a, const int n);  // SQRSHRUN2 Vd.4S,Vn.2D,#n
int8x8_t vqshrn_n_s16(int16x8_t a, const int n);                         // SQSHRN Vd.8B,Vn.8H,#n
int16x4_t vqshrn_n_s32(int32x4_t a, const int n);                        // SQSHRN Vd.4H,Vn.4S,#n
int32x2_t vqshrn_n_s64(int64x2_t a, const int n);                        // SQSHRN Vd.2S,Vn.2D,#n
uint8x8_t vqshrn_n_u16(uint16x8_t a, const int n);                       // UQSHRN Vd.8B,Vn.8H,#n
uint16x4_t vqshrn_n_u32(uint32x4_t a, const int n);                      // UQSHRN Vd.4H,Vn.4S,#n
uint32x2_t vqshrn_n_u64(uint64x2_t a, const int n);                      // UQSHRN Vd.2S,Vn.2D,#n
int8_t vqshrnh_n_s16(int16_t a, const int n);                            // SQSHRN Bd,Hn,#n
int16_t vqshrns_n_s32(int32_t a, const int n);                           // SQSHRN Hd,Sn,#n
int32_t vqshrnd_n_s64(int64_t a, const int n);                           // SQSHRN Sd,Dn,#n
uint8_t vqshrnh_n_u16(uint16_t a, const int n);                          // UQSHRN Bd,Hn,#n
uint16_t vqshrns_n_u32(uint32_t a, const int n);                         // UQSHRN Hd,Sn,#n
uint32_t vqshrnd_n_u64(uint64_t a, const int n);                         // UQSHRN Sd,Dn,#n
int8x16_t vqshrn_high_n_s16(int8x8_t r, int16x8_t a, const int n);       // SQSHRN2 Vd.16B,Vn.8H,#n
int16x8_t vqshrn_high_n_s32(int16x4_t r, int32x4_t a, const int n);      // SQSHRN2 Vd.8H,Vn.4S,#n
int32x4_t vqshrn_high_n_s64(int32x2_t r, int64x2_t a, const int n);      // SQSHRN2 Vd.4S,Vn.2D,#n
uint8x16_t vqshrn_high_n_u16(uint8x8_t r, uint16x8_t a, const int n);    // UQSHRN2 Vd.16B,Vn.8H,#n
uint16x8_t vqshrn_high_n_u32(uint16x4_t r, uint32x4_t a, const int n);   // UQSHRN2 Vd.8H,Vn.4S,#n
uint32x4_t vqshrn_high_n_u64(uint32x2_t r, uint64x2_t a, const int n);   // UQSHRN2 Vd.4S,Vn.2D,#n
int8x8_t vrshrn_n_s16(int16x8_t a, const int n);                         // RSHRN Vd.8B,Vn.8H,#n
int16x4_t vrshrn_n_s32(int32x4_t a, const int n);                        // RSHRN Vd.4H,Vn.4S,#n
int32x2_t vrshrn_n_s64(int64x2_t a, const int n);                        // RSHRN Vd.2S,Vn.2D,#n
uint8x8_t vrshrn_n_u16(uint16x8_t a, const int n);                       // RSHRN Vd.8B,Vn.8H,#n
uint16x4_t vrshrn_n_u32(uint32x4_t a, const int n);                      // RSHRN Vd.4H,Vn.4S,#n
uint32x2_t vrshrn_n_u64(uint64x2_t a, const int n);                      // RSHRN Vd.2S,Vn.2D,#n
int8x16_t vrshrn_high_n_s16(int8x8_t r, int16x8_t a, const int n);       // RSHRN2 Vd.16B,Vn.8H,#n
int16x8_t vrshrn_high_n_s32(int16x4_t r, int32x4_t a, const int n);      // RSHRN2 Vd.8H,Vn.4S,#n
int32x4_t vrshrn_high_n_s64(int32x2_t r, int64x2_t a, const int n);      // RSHRN2 Vd.4S,Vn.2D,#n
uint8x16_t vrshrn_high_n_u16(uint8x8_t r, uint16x8_t a, const int n);    // RSHRN2 Vd.16B,Vn.8H,#n
uint16x8_t vrshrn_high_n_u32(uint16x4_t r, uint32x4_t a, const int n);   // RSHRN2 Vd.8H,Vn.4S,#n
uint32x4_t vrshrn_high_n_u64(uint32x2_t r, uint64x2_t a, const int n);   // RSHRN2 Vd.4S,Vn.2D,#n
int8x8_t vqrshrn_n_s16(int16x8_t a, const int n);                        // SQRSHRN Vd.8B,Vn.8H,#n
int16x4_t vqrshrn_n_s32(int32x4_t a, const int n);                       // SQRSHRN Vd.4H,Vn.4S,#n
int32x2_t vqrshrn_n_s64(int64x2_t a, const int n);                       // SQRSHRN Vd.2S,Vn.2D,#n
uint8x8_t vqrshrn_n_u16(uint16x8_t a, const int n);                      // UQRSHRN Vd.8B,Vn.8H,#n
uint16x4_t vqrshrn_n_u32(uint32x4_t a, const int n);                     // UQRSHRN Vd.4H,Vn.4S,#n
uint32x2_t vqrshrn_n_u64(uint64x2_t a, const int n);                     // UQRSHRN Vd.2S,Vn.2D,#n
int8_t vqrshrnh_n_s16(int16_t a, const int n);                           // SQRSHRN Bd,Hn,#n
int16_t vqrshrns_n_s32(int32_t a, const int n);                          // SQRSHRN Hd,Sn,#n
int32_t vqrshrnd_n_s64(int64_t a, const int n);                          // SQRSHRN Sd,Dn,#n
uint8_t vqrshrnh_n_u16(uint16_t a, const int n);                         // UQRSHRN Bd,Hn,#n
uint16_t vqrshrns_n_u32(uint32_t a, const int n);                        // UQRSHRN Hd,Sn,#n
uint32_t vqrshrnd_n_u64(uint64_t a, const int n);                        // UQRSHRN Sd,Dn,#n
int8x16_t vqrshrn_high_n_s16(int8x8_t r, int16x8_t a, const int n);      // SQRSHRN2 Vd.16B,Vn.8H,#n
int16x8_t vqrshrn_high_n_s32(int16x4_t r, int32x4_t a, const int n);     // SQRSHRN2 Vd.8H,Vn.4S,#n
int32x4_t vqrshrn_high_n_s64(int32x2_t r, int64x2_t a, const int n);     // SQRSHRN2 Vd.4S,Vn.2D,#n
uint8x16_t vqrshrn_high_n_u16(uint8x8_t r, uint16x8_t a, const int n);   // UQRSHRN2 Vd.16B,Vn.8H,#n
uint16x8_t vqrshrn_high_n_u32(uint16x4_t r, uint32x4_t a, const int n);  // UQRSHRN2 Vd.8H,Vn.4S,#n
uint32x4_t vqrshrn_high_n_u64(uint32x2_t r, uint64x2_t a, const int n);  // UQRSHRN2 Vd.4S,Vn.2D,#n
uint16x8_t vshll_n_u8(uint8x8_t a, const int n);                         // USHLL Vd.8H,Vn.8B,#n
uint32x4_t vshll_n_u16(uint16x4_t a, const int n);                       // USHLL Vd.4S,Vn.4H,#n
uint64x2_t vshll_n_u32(uint32x2_t a, const int n);                       // USHLL Vd.2D,Vn.2S,#n
uint16x8_t vshll_high_n_u8(uint8x16_t a, const int n);                   // USHLL2 Vd.8H,Vn.16B,#n
uint32x4_t vshll_high_n_u16(uint16x8_t a, const int n);                  // USHLL2 Vd.4S,Vn.8H,#n
uint64x2_t vshll_high_n_u32(uint32x4_t a, const int n);                  // USHLL2 Vd.2D,Vn.4S,#n
int16x8_t vshll_n_s8(int8x8_t a, const int n);                           // SHLL Vd.8H,Vn.8B,#n
int32x4_t vshll_n_s16(int16x4_t a, const int n);                         // SHLL Vd.4S,Vn.4H,#n
int64x2_t vshll_n_s32(int32x2_t a, const int n);                         // SHLL Vd.2D,Vn.2S,#n
uint16x8_t vshll_n_u8(uint8x8_t a, const int n);                         // SHLL Vd.8H,Vn.8B,#n
uint32x4_t vshll_n_u16(uint16x4_t a, const int n);                       // SHLL Vd.4S,Vn.4H,#n
uint64x2_t vshll_n_u32(uint32x2_t a, const int n);                       // SHLL Vd.2D,Vn.2S,#n
int16x8_t vshll_high_n_s8(int8x16_t a, const int n);                     // SHLL2 Vd.8H,Vn.16B,#n
int32x4_t vshll_high_n_s16(int16x8_t a, const int n);                    // SHLL2 Vd.4S,Vn.8H,#n
int64x2_t vshll_high_n_s32(int32x4_t a, const int n);                    // SHLL2 Vd.2D,Vn.4S,#n
uint16x8_t vshll_high_n_u8(uint8x16_t a, const int n);                   // SHLL2 Vd.8H,Vn.16B,#n
uint32x4_t vshll_high_n_u16(uint16x8_t a, const int n);                  // SHLL2 Vd.4S,Vn.8H,#n
uint64x2_t vshll_high_n_u32(uint32x4_t a, const int n);                  // SHLL2 Vd.2D,Vn.4S,#n
int8x8_t vsri_n_s8(int8x8_t a, int8x8_t b, const int n);                 // SRI Vd.8B,Vn.8B,#n
int8x16_t vsriq_n_s8(int8x16_t a, int8x16_t b, const int n);             // SRI Vd.16B,Vn.16B,#n
int16x4_t vsri_n_s16(int16x4_t a, int16x4_t b, const int n);             // SRI Vd.4H,Vn.4H,#n
int16x8_t vsriq_n_s16(int16x8_t a, int16x8_t b, const int n);            // SRI Vd.8H,Vn.8H,#n
int32x2_t vsri_n_s32(int32x2_t a, int32x2_t b, const int n);             // SRI Vd.2S,Vn.2S,#n
int32x4_t vsriq_n_s32(int32x4_t a, int32x4_t b, const int n);            // SRI Vd.4S,Vn.4S,#n
int64x1_t vsri_n_s64(int64x1_t a, int64x1_t b, const int n);             // SRI Dd,Dn,#n
int64x2_t vsriq_n_s64(int64x2_t a, int64x2_t b, const int n);            // SRI Vd.2D,Vn.2D,#n
uint8x8_t vsri_n_u8(uint8x8_t a, uint8x8_t b, const int n);              // SRI Vd.8B,Vn.8B,#n
uint8x16_t vsriq_n_u8(uint8x16_t a, uint8x16_t b, const int n);          // SRI Vd.16B,Vn.16B,#n
uint16x4_t vsri_n_u16(uint16x4_t a, uint16x4_t b, const int n);          // SRI Vd.4H,Vn.4H,#n
uint16x8_t vsriq_n_u16(uint16x8_t a, uint16x8_t b, const int n);         // SRI Vd.8H,Vn.8H,#n
uint32x2_t vsri_n_u32(uint32x2_t a, uint32x2_t b, const int n);          // SRI Vd.2S,Vn.2S,#n
uint32x4_t vsriq_n_u32(uint32x4_t a, uint32x4_t b, const int n);         // SRI Vd.4S,Vn.4S,#n
uint64x1_t vsri_n_u64(uint64x1_t a, uint64x1_t b, const int n);          // SRI Dd,Dn,#n
uint64x2_t vsriq_n_u64(uint64x2_t a, uint64x2_t b, const int n);         // SRI Vd.2D,Vn.2D,#n
poly64x1_t vsri_n_p64(poly64x1_t a, poly64x1_t b, const int n);          // SRI Dd,Dn,#n
poly64x2_t vsriq_n_p64(poly64x2_t a, poly64x2_t b, const int n);         // SRI Vd.2D,Vn.2D,#n
poly8x8_t vsri_n_p8(poly8x8_t a, poly8x8_t b, const int n);              // SRI Vd.8B,Vn.8B,#n
poly8x16_t vsriq_n_p8(poly8x16_t a, poly8x16_t b, const int n);          // SRI Vd.16B,Vn.16B,#n
poly16x4_t vsri_n_p16(poly16x4_t a, poly16x4_t b, const int n);          // SRI Vd.4H,Vn.4H,#n
poly16x8_t vsriq_n_p16(poly16x8_t a, poly16x8_t b, const int n);         // SRI Vd.8H,Vn.8H,#n
int64_t vsrid_n_s64(int64_t a, int64_t b, const int n);                  // SRI Dd,Dn,#n
uint64_t vsrid_n_u64(uint64_t a, uint64_t b, const int n);               // SRI Dd,Dn,#n
int8x8_t vsli_n_s8(int8x8_t a, int8x8_t b, const int n);                 // SLI Vd.8B,Vn.8B,#n
int8x16_t vsliq_n_s8(int8x16_t a, int8x16_t b, const int n);             // SLI Vd.16B,Vn.16B,#n
int16x4_t vsli_n_s16(int16x4_t a, int16x4_t b, const int n);             // SLI Vd.4H,Vn.4H,#n
int16x8_t vsliq_n_s16(int16x8_t a, int16x8_t b, const int n);            // SLI Vd.8H,Vn.8H,#n
int32x2_t vsli_n_s32(int32x2_t a, int32x2_t b, const int n);             // SLI Vd.2S,Vn.2S,#n
int32x4_t vsliq_n_s32(int32x4_t a, int32x4_t b, const int n);            // SLI Vd.4S,Vn.4S,#n
int64x1_t vsli_n_s64(int64x1_t a, int64x1_t b, const int n);             // SLI Dd,Dn,#n
int64x2_t vsliq_n_s64(int64x2_t a, int64x2_t b, const int n);            // SLI Vd.2D,Vn.2D,#n
uint8x8_t vsli_n_u8(uint8x8_t a, uint8x8_t b, const int n);              // SLI Vd.8B,Vn.8B,#n
uint8x16_t vsliq_n_u8(uint8x16_t a, uint8x16_t b, const int n);          // SLI Vd.16B,Vn.16B,#n
uint16x4_t vsli_n_u16(uint16x4_t a, uint16x4_t b, const int n);          // SLI Vd.4H,Vn.4H,#n
uint16x8_t vsliq_n_u16(uint16x8_t a, uint16x8_t b, const int n);         // SLI Vd.8H,Vn.8H,#n
uint32x2_t vsli_n_u32(uint32x2_t a, uint32x2_t b, const int n);          // SLI Vd.2S,Vn.2S,#n
uint32x4_t vsliq_n_u32(uint32x4_t a, uint32x4_t b, const int n);         // SLI Vd.4S,Vn.4S,#n
uint64x1_t vsli_n_u64(uint64x1_t a, uint64x1_t b, const int n);          // SLI Dd,Dn,#n
uint64x2_t vsliq_n_u64(uint64x2_t a, uint64x2_t b, const int n);         // SLI Vd.2D,Vn.2D,#n
poly64x1_t vsli_n_p64(poly64x1_t a, poly64x1_t b, const int n);          // SLI Dd,Dn,#n
poly64x2_t vsliq_n_p64(poly64x2_t a, poly64x2_t b, const int n);         // SLI Vd.2D,Vn.2D,#n
poly8x8_t vsli_n_p8(poly8x8_t a, poly8x8_t b, const int n);              // SLI Vd.8B,Vn.8B,#n
poly8x16_t vsliq_n_p8(poly8x16_t a, poly8x16_t b, const int n);          // SLI Vd.16B,Vn.16B,#n
poly16x4_t vsli_n_p16(poly16x4_t a, poly16x4_t b, const int n);          // SLI Vd.4H,Vn.4H,#n
poly16x8_t vsliq_n_p16(poly16x8_t a, poly16x8_t b, const int n);         // SLI Vd.8H,Vn.8H,#n
int64_t vslid_n_s64(int64_t a, int64_t b, const int n);                  // SLI Dd,Dn,#n
uint64_t vslid_n_u64(uint64_t a, uint64_t b, const int n);               // SLI Dd,Dn,#n
int32x2_t vcvt_s32_f32(float32x2_t a);                                   // FCVTZS Vd.2S,Vn.2S
int32x4_t vcvtq_s32_f32(float32x4_t a);                                  // FCVTZS Vd.4S,Vn.4S
uint32x2_t vcvt_u32_f32(float32x2_t a);                                  // FCVTZU Vd.2S,Vn.2S
uint32x4_t vcvtq_u32_f32(float32x4_t a);                                 // FCVTZU Vd.4S,Vn.4S
int32x2_t vcvtn_s32_f32(float32x2_t a);                                  // FCVTNS Vd.2S,Vn.2S
int32x4_t vcvtnq_s32_f32(float32x4_t a);                                 // FCVTNS Vd.4S,Vn.4S
uint32x2_t vcvtn_u32_f32(float32x2_t a);                                 // FCVTNU Vd.2S,Vn.2S
uint32x4_t vcvtnq_u32_f32(float32x4_t a);                                // FCVTNU Vd.4S,Vn.4S
int32x2_t vcvtm_s32_f32(float32x2_t a);                                  // FCVTMS Vd.2S,Vn.2S
int32x4_t vcvtmq_s32_f32(float32x4_t a);                                 // FCVTMS Vd.4S,Vn.4S
uint32x2_t vcvtm_u32_f32(float32x2_t a);                                 // FCVTMU Vd.2S,Vn.2S
uint32x4_t vcvtmq_u32_f32(float32x4_t a);                                // FCVTMU Vd.4S,Vn.4S
int32x2_t vcvtp_s32_f32(float32x2_t a);                                  // FCVTPS Vd.2S,Vn.2S
int32x4_t vcvtpq_s32_f32(float32x4_t a);                                 // FCVTPS Vd.4S,Vn.4S
uint32x2_t vcvtp_u32_f32(float32x2_t a);                                 // FCVTPU Vd.2S,Vn.2S
uint32x4_t vcvtpq_u32_f32(float32x4_t a);                                // FCVTPU Vd.4S,Vn.4S
int32x2_t vcvta_s32_f32(float32x2_t a);                                  // FCVTAS Vd.2S,Vn.2S
int32x4_t vcvtaq_s32_f32(float32x4_t a);                                 // FCVTAS Vd.4S,Vn.4S
uint32x2_t vcvta_u32_f32(float32x2_t a);                                 // FCVTAU Vd.2S,Vn.2S
uint32x4_t vcvtaq_u32_f32(float32x4_t a);                                // FCVTAU Vd.4S,Vn.4S
int32_t vcvts_s32_f32(float32_t a);                                      // FCVTZS Sd,Sn
uint32_t vcvts_u32_f32(float32_t a);                                     // FCVTZU Sd,Sn
int32_t vcvtns_s32_f32(float32_t a);                                     // FCVTNS Sd,Sn
uint32_t vcvtns_u32_f32(float32_t a);                                    // FCVTNU Sd,Sn
int32_t vcvtms_s32_f32(float32_t a);                                     // FCVTMS Sd,Sn
uint32_t vcvtms_u32_f32(float32_t a);                                    // FCVTMU Sd,Sn
int32_t vcvtps_s32_f32(float32_t a);                                     // FCVTPS Sd,Sn
uint32_t vcvtps_u32_f32(float32_t a);                                    // FCVTPU Sd,Sn
int32_t vcvtas_s32_f32(float32_t a);                                     // FCVTAS Sd,Sn
uint32_t vcvtas_u32_f32(float32_t a);                                    // FCVTAU Sd,Sn
int64x1_t vcvt_s64_f64(float64x1_t a);                                   // FCVTZS Dd,Dn
int64x2_t vcvtq_s64_f64(float64x2_t a);                                  // FCVTZS Vd.2D,Vn.2D
uint64x1_t vcvt_u64_f64(float64x1_t a);                                  // FCVTZU Dd,Dn
uint64x2_t vcvtq_u64_f64(float64x2_t a);                                 // FCVTZU Vd.2D,Vn.2D
int64x1_t vcvtn_s64_f64(float64x1_t a);                                  // FCVTNS Dd,Dn
int64x2_t vcvtnq_s64_f64(float64x2_t a);                                 // FCVTNS Vd.2D,Vn.2D
uint64x1_t vcvtn_u64_f64(float64x1_t a);                                 // FCVTNU Dd,Dn
uint64x2_t vcvtnq_u64_f64(float64x2_t a);                                // FCVTNU Vd.2D,Vn.2D
int64x1_t vcvtm_s64_f64(float64x1_t a);                                  // FCVTMS Dd,Dn
int64x2_t vcvtmq_s64_f64(float64x2_t a);                                 // FCVTMS Vd.2D,Vn.2D
uint64x1_t vcvtm_u64_f64(float64x1_t a);                                 // FCVTMU Dd,Dn
uint64x2_t vcvtmq_u64_f64(float64x2_t a);                                // FCVTMU Vd.2D,Vn.2D
int64x1_t vcvtp_s64_f64(float64x1_t a);                                  // FCVTPS Dd,Dn
int64x2_t vcvtpq_s64_f64(float64x2_t a);                                 // FCVTPS Vd.2D,Vn.2D
uint64x1_t vcvtp_u64_f64(float64x1_t a);                                 // FCVTPU Dd,Dn
uint64x2_t vcvtpq_u64_f64(float64x2_t a);                                // FCVTPU Vd.2D,Vn.2D
int64x1_t vcvta_s64_f64(float64x1_t a);                                  // FCVTAS Dd,Dn
int64x2_t vcvtaq_s64_f64(float64x2_t a);                                 // FCVTAS Vd.2D,Vn.2D
uint64x1_t vcvta_u64_f64(float64x1_t a);                                 // FCVTAU Dd,Dn
uint64x2_t vcvtaq_u64_f64(float64x2_t a);                                // FCVTAU Vd.2D,Vn.2D
int64_t vcvtd_s64_f64(float64_t a);                                      // FCVTZS Dd,Dn
uint64_t vcvtd_u64_f64(float64_t a);                                     // FCVTZU Dd,Dn
int64_t vcvtnd_s64_f64(float64_t a);                                     // FCVTNS Dd,Dn
uint64_t vcvtnd_u64_f64(float64_t a);                                    // FCVTNU Dd,Dn
int64_t vcvtmd_s64_f64(float64_t a);                                     // FCVTMS Dd,Dn
uint64_t vcvtmd_u64_f64(float64_t a);                                    // FCVTMU Dd,Dn
int64_t vcvtpd_s64_f64(float64_t a);                                     // FCVTPS Dd,Dn
uint64_t vcvtpd_u64_f64(float64_t a);                                    // FCVTPU Dd,Dn
int64_t vcvtad_s64_f64(float64_t a);                                     // FCVTAS Dd,Dn
uint64_t vcvtad_u64_f64(float64_t a);                                    // FCVTAU Dd,Dn
int32x2_t vcvt_n_s32_f32(float32x2_t a, const int n);                    // FCVTZS Vd.2S,Vn.2S,#n
int32x4_t vcvtq_n_s32_f32(float32x4_t a, const int n);                   // FCVTZS Vd.4S,Vn.4S,#n
uint32x2_t vcvt_n_u32_f32(float32x2_t a, const int n);                   // FCVTZU Vd.2S,Vn.2S,#n
uint32x4_t vcvtq_n_u32_f32(float32x4_t a, const int n);                  // FCVTZU Vd.4S,Vn.4S,#n
int32_t vcvts_n_s32_f32(float32_t a, const int n);                       // FCVTZS Sd,Sn,#n
uint32_t vcvts_n_u32_f32(float32_t a, const int n);                      // FCVTZU Sd,Sn,#n
int64x1_t vcvt_n_s64_f64(float64x1_t a, const int n);                    // FCVTZS Dd,Dn,#n
int64x2_t vcvtq_n_s64_f64(float64x2_t a, const int n);                   // FCVTZS Vd.2D,Vn.2D,#n
uint64x1_t vcvt_n_u64_f64(float64x1_t a, const int n);                   // FCVTZU Dd,Dn,#n
uint64x2_t vcvtq_n_u64_f64(float64x2_t a, const int n);                  // FCVTZU Vd.2D,Vn.2D,#n
int64_t vcvtd_n_s64_f64(float64_t a, const int n);                       // FCVTZS Dd,Dn,#n
uint64_t vcvtd_n_u64_f64(float64_t a, const int n);                      // FCVTZU Dd,Dn,#n
float32x2_t vcvt_f32_s32(int32x2_t a);                                   // SCVTF Vd.2S,Vn.2S
float32x4_t vcvtq_f32_s32(int32x4_t a);                                  // SCVTF Vd.4S,Vn.4S
float32x2_t vcvt_f32_u32(uint32x2_t a);                                  // UCVTF Vd.2S,Vn.2S
float32x4_t vcvtq_f32_u32(uint32x4_t a);                                 // UCVTF Vd.4S,Vn.4S
float32_t vcvts_f32_u32(uint32_t a);                                     // UCVTF Sd,Sn
float64x2_t vcvtq_f64_s64(int64x2_t a);                                  // SCVTF Vd.2D,Vn.2D
float64x1_t vcvt_f64_u64(uint64x1_t a);                                  // UCVTF Dd,Dn
float64x2_t vcvtq_f64_u64(uint64x2_t a);                                 // UCVTF Vd.2D,Vn.2D
float64_t vcvtd_f64_u64(uint64_t a);                                     // UCVTF Dd,Dn
float32x2_t vcvt_n_f32_s32(int32x2_t a, const int n);                    // SCVTF Vd.2S,Vn.2S,#n
float32x4_t vcvtq_n_f32_s32(int32x4_t a, const int n);                   // SCVTF Vd.4S,Vn.4S,#n
float32x2_t vcvt_n_f32_u32(uint32x2_t a, const int n);                   // UCVTF Vd.2S,Vn.2S,#n
float32x4_t vcvtq_n_f32_u32(uint32x4_t a, const int n);                  // UCVTF Vd.4S,Vn.4S,#n
float32_t vcvts_n_f32_s32(int32_t a, const int n);                       // SCVTF Sd,Sn,#n
float32_t vcvts_n_f32_u32(uint32_t a, const int n);                      // UCVTF Sd,Sn,#n
float64x1_t vcvt_n_f64_s64(int64x1_t a, const int n);                    // SCVTF Dd,Dn,#n
float64x2_t vcvtq_n_f64_s64(int64x2_t a, const int n);                   // SCVTF Vd.2D,Vn.2D,#n
float64x1_t vcvt_n_f64_u64(uint64x1_t a, const int n);                   // UCVTF Dd,Dn,#n
float64x2_t vcvtq_n_f64_u64(uint64x2_t a, const int n);                  // UCVTF Vd.2D,Vn.2D,#n
float64_t vcvtd_n_f64_s64(int64_t a, const int n);                       // SCVTF Dd,Dn,#n
float64_t vcvtd_n_f64_u64(uint64_t a, const int n);                      // UCVTF Dd,Dn,#n
float16x4_t vcvt_f16_f32(float32x4_t a);                                 // FCVTN Vd.4H,Vn.4S
float16x8_t vcvt_high_f16_f32(float16x4_t r, float32x4_t a);             // FCVTN2 Vd.8H,Vn.4S
float32x2_t vcvt_f32_f64(float64x2_t a);                                 // FCVTN Vd.2S,Vn.2D
float32x4_t vcvt_high_f32_f64(float32x2_t r, float64x2_t a);             // FCVTN2 Vd.4S,Vn.2D
float32x4_t vcvt_f32_f16(float16x4_t a);                                 // FCVTL Vd.4S,Vn.4H
float32x4_t vcvt_high_f32_f16(float16x8_t a);                            // FCVTL2 Vd.4S,Vn.8H
float64x2_t vcvt_f64_f32(float32x2_t a);                                 // FCVTL Vd.2D,Vn.2S
float64x2_t vcvt_high_f64_f32(float32x4_t a);                            // FCVTL2 Vd.2D,Vn.4S
float32x2_t vcvtx_f32_f64(float64x2_t a);                                // FCVTXN Vd.2S,Vn.2D
float32_t vcvtxd_f32_f64(float64_t a);                                   // FCVTXN Sd,Dn
float32x4_t vcvtx_high_f32_f64(float32x2_t r, float64x2_t a);            // FCVTXN2 Vd.4S,Vn.2D
float32x2_t vrnd_f32(float32x2_t a);                                     // FRINTZ Vd.2S,Vn.2S
float32x4_t vrndq_f32(float32x4_t a);                                    // FRINTZ Vd.4S,Vn.4S
float64x1_t vrnd_f64(float64x1_t a);                                     // FRINTZ Dd,Dn
float64x2_t vrndq_f64(float64x2_t a);                                    // FRINTZ Vd.2D,Vn.2D
float32x2_t vrndn_f32(float32x2_t a);                                    // FRINTN Vd.2S,Vn.2S
float32x4_t vrndnq_f32(float32x4_t a);                                   // FRINTN Vd.4S,Vn.4S
float64x1_t vrndn_f64(float64x1_t a);                                    // FRINTN Dd,Dn
float64x2_t vrndnq_f64(float64x2_t a);                                   // FRINTN Vd.2D,Vn.2D
float32_t vrndns_f32(float32_t a);                                       // FRINTN Sd,Sn
float32x2_t vrndm_f32(float32x2_t a);                                    // FRINTM Vd.2S,Vn.2S
float32x4_t vrndmq_f32(float32x4_t a);                                   // FRINTM Vd.4S,Vn.4S
float64x1_t vrndm_f64(float64x1_t a);                                    // FRINTM Dd,Dn
float64x2_t vrndmq_f64(float64x2_t a);                                   // FRINTM Vd.2D,Vn.2D
float32x2_t vrndp_f32(float32x2_t a);                                    // FRINTP Vd.2S,Vn.2S
float32x4_t vrndpq_f32(float32x4_t a);                                   // FRINTP Vd.4S,Vn.4S
float64x1_t vrndp_f64(float64x1_t a);                                    // FRINTP Dd,Dn
float64x2_t vrndpq_f64(float64x2_t a);                                   // FRINTP Vd.2D,Vn.2D
float32x2_t vrnda_f32(float32x2_t a);                                    // FRINTA Vd.2S,Vn.2S
float32x4_t vrndaq_f32(float32x4_t a);                                   // FRINTA Vd.4S,Vn.4S
float64x1_t vrnda_f64(float64x1_t a);                                    // FRINTA Dd,Dn
float64x2_t vrndaq_f64(float64x2_t a);                                   // FRINTA Vd.2D,Vn.2D
float32x2_t vrndi_f32(float32x2_t a);                                    // FRINTI Vd.2S,Vn.2S
float32x4_t vrndiq_f32(float32x4_t a);                                   // FRINTI Vd.4S,Vn.4S
float64x1_t vrndi_f64(float64x1_t a);                                    // FRINTI Dd,Dn
float64x2_t vrndiq_f64(float64x2_t a);                                   // FRINTI Vd.2D,Vn.2D
float32x2_t vrndx_f32(float32x2_t a);                                    // FRINTX Vd.2S,Vn.2S
float32x4_t vrndxq_f32(float32x4_t a);                                   // FRINTX Vd.4S,Vn.4S
float64x1_t vrndx_f64(float64x1_t a);                                    // FRINTX Dd,Dn
float64x2_t vrndxq_f64(float64x2_t a);                                   // FRINTX Vd.2D,Vn.2D
int8x8_t vmovn_s16(int16x8_t a);                                         // XTN Vd.8B,Vn.8H
int16x4_t vmovn_s32(int32x4_t a);                                        // XTN Vd.4H,Vn.4S
int32x2_t vmovn_s64(int64x2_t a);                                        // XTN Vd.2S,Vn.2D
uint8x8_t vmovn_u16(uint16x8_t a);                                       // XTN Vd.8B,Vn.8H
uint16x4_t vmovn_u32(uint32x4_t a);                                      // XTN Vd.4H,Vn.4S
uint32x2_t vmovn_u64(uint64x2_t a);                                      // XTN Vd.2S,Vn.2D
int8x16_t vmovn_high_s16(int8x8_t r, int16x8_t a);                       // XTN2 Vd.16B,Vn.8H
int16x8_t vmovn_high_s32(int16x4_t r, int32x4_t a);                      // XTN2 Vd.8H,Vn.4S
int32x4_t vmovn_high_s64(int32x2_t r, int64x2_t a);                      // XTN2 Vd.4S,Vn.2D
uint8x16_t vmovn_high_u16(uint8x8_t r, uint16x8_t a);                    // XTN2 Vd.16B,Vn.8H
uint16x8_t vmovn_high_u32(uint16x4_t r, uint32x4_t a);                   // XTN2 Vd.8H,Vn.4S
uint32x4_t vmovn_high_u64(uint32x2_t r, uint64x2_t a);                   // XTN2 Vd.4S,Vn.2D
uint16x8_t vmovl_u8(uint8x8_t a);                                        // USHLL Vd.8H,Vn.8B,#0
uint32x4_t vmovl_u16(uint16x4_t a);                                      // USHLL Vd.4S,Vn.4H,#0
uint64x2_t vmovl_u32(uint32x2_t a);                                      // USHLL Vd.2D,Vn.2S,#0
uint16x8_t vmovl_high_u8(uint8x16_t a);                                  // USHLL2 Vd.8H,Vn.16B,#0
uint32x4_t vmovl_high_u16(uint16x8_t a);                                 // USHLL2 Vd.4S,Vn.8H,#0
uint64x2_t vmovl_high_u32(uint32x4_t a);                                 // USHLL2 Vd.2D,Vn.4S,#0
int8x8_t vqmovn_s16(int16x8_t a);                                        // SQXTN Vd.8B,Vn.8H
int16x4_t vqmovn_s32(int32x4_t a);                                       // SQXTN Vd.4H,Vn.4S
int32x2_t vqmovn_s64(int64x2_t a);                                       // SQXTN Vd.2S,Vn.2D
uint8x8_t vqmovn_u16(uint16x8_t a);                                      // UQXTN Vd.8B,Vn.8H
uint16x4_t vqmovn_u32(uint32x4_t a);                                     // UQXTN Vd.4H,Vn.4S
uint32x2_t vqmovn_u64(uint64x2_t a);                                     // UQXTN Vd.2S,Vn.2D
int8_t vqmovnh_s16(int16_t a);                                           // SQXTN Bd,Hn
int16_t vqmovns_s32(int32_t a);                                          // SQXTN Hd,Sn
int32_t vqmovnd_s64(int64_t a);                                          // SQXTN Sd,Dn
uint8_t vqmovnh_u16(uint16_t a);                                         // UQXTN Bd,Hn
uint16_t vqmovns_u32(uint32_t a);                                        // UQXTN Hd,Sn
uint32_t vqmovnd_u64(uint64_t a);                                        // UQXTN Sd,Dn
int8x16_t vqmovn_high_s16(int8x8_t r, int16x8_t a);                      // SQXTN2 Vd.16B,Vn.8H
int16x8_t vqmovn_high_s32(int16x4_t r, int32x4_t a);                     // SQXTN2 Vd.8H,Vn.4S
int32x4_t vqmovn_high_s64(int32x2_t r, int64x2_t a);                     // SQXTN2 Vd.4S,Vn.2D
uint8x16_t vqmovn_high_u16(uint8x8_t r, uint16x8_t a);                   // UQXTN2 Vd.16B,Vn.8H
uint16x8_t vqmovn_high_u32(uint16x4_t r, uint32x4_t a);                  // UQXTN2 Vd.8H,Vn.4S
uint32x4_t vqmovn_high_u64(uint32x2_t r, uint64x2_t a);                  // UQXTN2 Vd.4S,Vn.2D
uint8x8_t vqmovun_s16(int16x8_t a);                                      // SQXTUN Vd.8B,Vn.8H
uint16x4_t vqmovun_s32(int32x4_t a);                                     // SQXTUN Vd.4H,Vn.4S
uint32x2_t vqmovun_s64(int64x2_t a);                                     // SQXTUN Vd.2S,Vn.2D
uint8_t vqmovunh_s16(int16_t a);                                         // SQXTUN Bd,Hn
uint16_t vqmovuns_s32(int32_t a);                                        // SQXTUN Hd,Sn
uint32_t vqmovund_s64(int64_t a);                                        // SQXTUN Sd,Dn
uint8x16_t vqmovun_high_s16(uint8x8_t r, int16x8_t a);                   // SQXTUN2 Vd.16B,Vn.8H
uint16x8_t vqmovun_high_s32(uint16x4_t r, int32x4_t a);                  // SQXTUN2 Vd.8H,Vn.4S
uint32x4_t vqmovun_high_s64(uint32x2_t r, int64x2_t a);                  // SQXTUN2 Vd.4S,Vn.2D
int16x4_t vmla_lane_s16(
    int16x4_t a, int16x4_t b, int16x4_t v, const int lane);  // MLA Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vmlaq_lane_s16(
    int16x8_t a, int16x8_t b, int16x4_t v, const int lane);  // MLA Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vmla_lane_s32(
    int32x2_t a, int32x2_t b, int32x2_t v, const int lane);  // MLA Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vmlaq_lane_s32(
    int32x4_t a, int32x4_t b, int32x2_t v, const int lane);  // MLA Vd.4S,Vn.4S,Vm.S[lane]
uint16x4_t vmla_lane_u16(
    uint16x4_t a, uint16x4_t b, uint16x4_t v, const int lane);  // MLA Vd.4H,Vn.4H,Vm.H[lane]
uint16x8_t vmlaq_lane_u16(
    uint16x8_t a, uint16x8_t b, uint16x4_t v, const int lane);  // MLA Vd.8H,Vn.8H,Vm.H[lane]
uint32x2_t vmla_lane_u32(
    uint32x2_t a, uint32x2_t b, uint32x2_t v, const int lane);  // MLA Vd.2S,Vn.2S,Vm.S[lane]
uint32x4_t vmlaq_lane_u32(
    uint32x4_t a, uint32x4_t b, uint32x2_t v, const int lane);  // MLA Vd.4S,Vn.4S,Vm.S[lane]
float32x2_t vmla_lane_f32(float32x2_t a, float32x2_t b, float32x2_t v,
    const int lane);  // RESULT[I] = a[i] + (b[i] * v[lane]) for i = 0 to 1
float32x4_t vmlaq_lane_f32(float32x4_t a, float32x4_t b, float32x2_t v,
    const int lane);  // RESULT[I] = a[i] + (b[i] * v[lane]) for i = 0 to 3
int16x4_t vmla_laneq_s16(
    int16x4_t a, int16x4_t b, int16x8_t v, const int lane);  // MLA Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vmlaq_laneq_s16(
    int16x8_t a, int16x8_t b, int16x8_t v, const int lane);  // MLA Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vmla_laneq_s32(
    int32x2_t a, int32x2_t b, int32x4_t v, const int lane);  // MLA Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vmlaq_laneq_s32(
    int32x4_t a, int32x4_t b, int32x4_t v, const int lane);  // MLA Vd.4S,Vn.4S,Vm.S[lane]
uint16x4_t vmla_laneq_u16(
    uint16x4_t a, uint16x4_t b, uint16x8_t v, const int lane);  // MLA Vd.4H,Vn.4H,Vm.H[lane]
uint16x8_t vmlaq_laneq_u16(
    uint16x8_t a, uint16x8_t b, uint16x8_t v, const int lane);  // MLA Vd.8H,Vn.8H,Vm.H[lane]
uint32x2_t vmla_laneq_u32(
    uint32x2_t a, uint32x2_t b, uint32x4_t v, const int lane);  // MLA Vd.2S,Vn.2S,Vm.S[lane]
uint32x4_t vmlaq_laneq_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t v, const int lane);  // MLA Vd.4S,Vn.4S,Vm.S[lane]
float32x2_t vmla_laneq_f32(float32x2_t a, float32x2_t b, float32x4_t v,
    const int lane);  // RESULT[I] = a[i] + (b[i] * v[lane]) for i = 0 to 1
float32x4_t vmlaq_laneq_f32(float32x4_t a, float32x4_t b, float32x4_t v,
    const int lane);  // RESULT[I] = a[i] + (b[i] * v[lane]) for i = 0 to 3
int32x4_t vmlal_lane_s16(
    int32x4_t a, int16x4_t b, int16x4_t v, const int lane);  // SMLAL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vmlal_lane_s32(
    int64x2_t a, int32x2_t b, int32x2_t v, const int lane);  // SMLAL Vd.2D,Vn.2S,Vm.S[lane]
uint32x4_t vmlal_lane_u16(
    uint32x4_t a, uint16x4_t b, uint16x4_t v, const int lane);  // UMLAL Vd.4S,Vn.4H,Vm.H[lane]
uint64x2_t vmlal_lane_u32(
    uint64x2_t a, uint32x2_t b, uint32x2_t v, const int lane);  // UMLAL Vd.2D,Vn.2S,Vm.S[lane]
int32x4_t vmlal_high_lane_s16(
    int32x4_t a, int16x8_t b, int16x4_t v, const int lane);  // SMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vmlal_high_lane_s32(
    int64x2_t a, int32x4_t b, int32x2_t v, const int lane);  // SMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
uint32x4_t vmlal_high_lane_u16(
    uint32x4_t a, uint16x8_t b, uint16x4_t v, const int lane);  // UMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
uint64x2_t vmlal_high_lane_u32(
    uint64x2_t a, uint32x4_t b, uint32x2_t v, const int lane);  // UMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vmlal_laneq_s16(
    int32x4_t a, int16x4_t b, int16x8_t v, const int lane);  // SMLAL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vmlal_laneq_s32(
    int64x2_t a, int32x2_t b, int32x4_t v, const int lane);  // SMLAL Vd.2D,Vn.2S,Vm.S[lane]
uint32x4_t vmlal_laneq_u16(
    uint32x4_t a, uint16x4_t b, uint16x8_t v, const int lane);  // UMLAL Vd.4S,Vn.4H,Vm.H[lane]
uint64x2_t vmlal_laneq_u32(
    uint64x2_t a, uint32x2_t b, uint32x4_t v, const int lane);  // UMLAL Vd.2D,Vn.2S,Vm.S[lane]
int32x4_t vmlal_high_laneq_s16(
    int32x4_t a, int16x8_t b, int16x8_t v, const int lane);  // SMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vmlal_high_laneq_s32(
    int64x2_t a, int32x4_t b, int32x4_t v, const int lane);  // SMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
uint32x4_t vmlal_high_laneq_u16(
    uint32x4_t a, uint16x8_t b, uint16x8_t v, const int lane);  // UMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
uint64x2_t vmlal_high_laneq_u32(
    uint64x2_t a, uint32x4_t b, uint32x4_t v, const int lane);  // UMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vqdmlal_lane_s16(
    int32x4_t a, int16x4_t b, int16x4_t v, const int lane);  // SQDMLAL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vqdmlal_lane_s32(
    int64x2_t a, int32x2_t b, int32x2_t v, const int lane);  // SQDMLAL Vd.2D,Vn.2S,Vm.S[lane]
int32_t vqdmlalh_lane_s16(
    int32_t a, int16_t b, int16x4_t v, const int lane);  // SQDMLAL Sd,Hn,Vm.H[lane]
int64_t vqdmlals_lane_s32(
    int64_t a, int32_t b, int32x2_t v, const int lane);  // SQDMLAL Dd,Sn,Vm.S[lane]
int32x4_t vqdmlal_high_lane_s16(
    int32x4_t a, int16x8_t b, int16x4_t v, const int lane);  // SQDMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vqdmlal_high_lane_s32(
    int64x2_t a, int32x4_t b, int32x2_t v, const int lane);  // SQDMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vqdmlal_laneq_s16(
    int32x4_t a, int16x4_t b, int16x8_t v, const int lane);  // SQDMLAL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vqdmlal_laneq_s32(
    int64x2_t a, int32x2_t b, int32x4_t v, const int lane);  // SQDMLAL Vd.2D,Vn.2S,Vm.S[lane]
int32_t vqdmlalh_laneq_s16(
    int32_t a, int16_t b, int16x8_t v, const int lane);  // SQDMLAL Sd,Hn,Vm.H[lane]
int64_t vqdmlals_laneq_s32(
    int64_t a, int32_t b, int32x4_t v, const int lane);  // SQDMLAL Dd,Sn,Vm.S[lane]
int32x4_t vqdmlal_high_laneq_s16(
    int32x4_t a, int16x8_t b, int16x8_t v, const int lane);  // SQDMLAL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vqdmlal_high_laneq_s32(
    int64x2_t a, int32x4_t b, int32x4_t v, const int lane);  // SQDMLAL2 Vd.2D,Vn.4S,Vm.S[lane]
int16x4_t vmls_lane_s16(
    int16x4_t a, int16x4_t b, int16x4_t v, const int lane);  // MLS Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vmlsq_lane_s16(
    int16x8_t a, int16x8_t b, int16x4_t v, const int lane);  // MLS Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vmls_lane_s32(
    int32x2_t a, int32x2_t b, int32x2_t v, const int lane);  // MLS Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vmlsq_lane_s32(
    int32x4_t a, int32x4_t b, int32x2_t v, const int lane);  // MLS Vd.4S,Vn.4S,Vm.S[lane]
uint16x4_t vmls_lane_u16(
    uint16x4_t a, uint16x4_t b, uint16x4_t v, const int lane);  // MLS Vd.4H,Vn.4H,Vm.H[lane]
uint16x8_t vmlsq_lane_u16(
    uint16x8_t a, uint16x8_t b, uint16x4_t v, const int lane);  // MLS Vd.8H,Vn.8H,Vm.H[lane]
uint32x2_t vmls_lane_u32(
    uint32x2_t a, uint32x2_t b, uint32x2_t v, const int lane);  // MLS Vd.2S,Vn.2S,Vm.S[lane]
uint32x4_t vmlsq_lane_u32(
    uint32x4_t a, uint32x4_t b, uint32x2_t v, const int lane);  // MLS Vd.4S,Vn.4S,Vm.S[lane]
float32x2_t vmls_lane_f32(float32x2_t a, float32x2_t b, float32x2_t v,
    const int lane);  // RESULT[I] = a[i] - (b[i] * v[lane]) for i = 0 to 1
float32x4_t vmlsq_lane_f32(float32x4_t a, float32x4_t b, float32x2_t v,
    const int lane);  // RESULT[I] = a[i] - (b[i] * v[lane]) for i = 0 to 3
int16x4_t vmls_laneq_s16(
    int16x4_t a, int16x4_t b, int16x8_t v, const int lane);  // MLS Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vmlsq_laneq_s16(
    int16x8_t a, int16x8_t b, int16x8_t v, const int lane);  // MLS Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vmls_laneq_s32(
    int32x2_t a, int32x2_t b, int32x4_t v, const int lane);  // MLS Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vmlsq_laneq_s32(
    int32x4_t a, int32x4_t b, int32x4_t v, const int lane);  // MLS Vd.4S,Vn.4S,Vm.S[lane]
uint16x4_t vmls_laneq_u16(
    uint16x4_t a, uint16x4_t b, uint16x8_t v, const int lane);  // MLS Vd.4H,Vn.4H,Vm.H[lane]
uint16x8_t vmlsq_laneq_u16(
    uint16x8_t a, uint16x8_t b, uint16x8_t v, const int lane);  // MLS Vd.8H,Vn.8H,Vm.H[lane]
uint32x2_t vmls_laneq_u32(
    uint32x2_t a, uint32x2_t b, uint32x4_t v, const int lane);  // MLS Vd.2S,Vn.2S,Vm.S[lane]
uint32x4_t vmlsq_laneq_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t v, const int lane);  // MLS Vd.4S,Vn.4S,Vm.S[lane]
float32x2_t vmls_laneq_f32(float32x2_t a, float32x2_t b, float32x4_t v,
    const int lane);  // RESULT[I] = a[i] - (b[i] * v[lane]) for i = 0 to 1
float32x4_t vmlsq_laneq_f32(float32x4_t a, float32x4_t b, float32x4_t v,
    const int lane);  // RESULT[I] = a[i] - (b[i] * v[lane]) for i = 0 to 3
int32x4_t vmlsl_lane_s16(
    int32x4_t a, int16x4_t b, int16x4_t v, const int lane);  // SMLSL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vmlsl_lane_s32(
    int64x2_t a, int32x2_t b, int32x2_t v, const int lane);  // SMLSL Vd.2D,Vn.2S,Vm.S[lane]
uint32x4_t vmlsl_lane_u16(
    uint32x4_t a, uint16x4_t b, uint16x4_t v, const int lane);  // UMLSL Vd.4S,Vn.4H,Vm.H[lane]
uint64x2_t vmlsl_lane_u32(
    uint64x2_t a, uint32x2_t b, uint32x2_t v, const int lane);  // UMLSL Vd.2D,Vn.2S,Vm.S[lane]
int32x4_t vmlsl_high_lane_s16(
    int32x4_t a, int16x8_t b, int16x4_t v, const int lane);  // SMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vmlsl_high_lane_s32(
    int64x2_t a, int32x4_t b, int32x2_t v, const int lane);  // SMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
uint32x4_t vmlsl_high_lane_u16(
    uint32x4_t a, uint16x8_t b, uint16x4_t v, const int lane);  // UMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
uint64x2_t vmlsl_high_lane_u32(
    uint64x2_t a, uint32x4_t b, uint32x2_t v, const int lane);  // UMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vmlsl_laneq_s16(
    int32x4_t a, int16x4_t b, int16x8_t v, const int lane);  // SMLSL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vmlsl_laneq_s32(
    int64x2_t a, int32x2_t b, int32x4_t v, const int lane);  // SMLSL Vd.2D,Vn.2S,Vm.S[lane]
uint32x4_t vmlsl_laneq_u16(
    uint32x4_t a, uint16x4_t b, uint16x8_t v, const int lane);  // UMLSL Vd.4S,Vn.4H,Vm.H[lane]
uint64x2_t vmlsl_laneq_u32(
    uint64x2_t a, uint32x2_t b, uint32x4_t v, const int lane);  // UMLSL Vd.2D,Vn.2S,Vm.S[lane]
int32x4_t vmlsl_high_laneq_s16(
    int32x4_t a, int16x8_t b, int16x8_t v, const int lane);  // SMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vmlsl_high_laneq_s32(
    int64x2_t a, int32x4_t b, int32x4_t v, const int lane);  // SMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
uint32x4_t vmlsl_high_laneq_u16(
    uint32x4_t a, uint16x8_t b, uint16x8_t v, const int lane);  // UMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
uint64x2_t vmlsl_high_laneq_u32(
    uint64x2_t a, uint32x4_t b, uint32x4_t v, const int lane);  // UMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vqdmlsl_lane_s16(
    int32x4_t a, int16x4_t b, int16x4_t v, const int lane);  // SQDMLSL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vqdmlsl_lane_s32(
    int64x2_t a, int32x2_t b, int32x2_t v, const int lane);  // SQDMLSL Vd.2D,Vn.2S,Vm.S[lane]
int32_t vqdmlslh_lane_s16(
    int32_t a, int16_t b, int16x4_t v, const int lane);  // SQDMLSL Sd,Hn,Vm.H[lane]
int64_t vqdmlsls_lane_s32(
    int64_t a, int32_t b, int32x2_t v, const int lane);  // SQDMLSL Dd,Sn,Vm.S[lane]
int32x4_t vqdmlsl_high_lane_s16(
    int32x4_t a, int16x8_t b, int16x4_t v, const int lane);  // SQDMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vqdmlsl_high_lane_s32(
    int64x2_t a, int32x4_t b, int32x2_t v, const int lane);  // SQDMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vqdmlsl_laneq_s16(
    int32x4_t a, int16x4_t b, int16x8_t v, const int lane);  // SQDMLSL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vqdmlsl_laneq_s32(
    int64x2_t a, int32x2_t b, int32x4_t v, const int lane);  // SQDMLSL Vd.2D,Vn.2S,Vm.S[lane]
int32_t vqdmlslh_laneq_s16(
    int32_t a, int16_t b, int16x8_t v, const int lane);  // SQDMLSL Sd,Hn,Vm.H[lane]
int64_t vqdmlsls_laneq_s32(
    int64_t a, int32_t b, int32x4_t v, const int lane);  // SQDMLSL Dd,Sn,Vm.S[lane]
int32x4_t vqdmlsl_high_laneq_s16(
    int32x4_t a, int16x8_t b, int16x8_t v, const int lane);  // SQDMLSL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vqdmlsl_high_laneq_s32(
    int64x2_t a, int32x4_t b, int32x4_t v, const int lane);  // SQDMLSL2 Vd.2D,Vn.4S,Vm.S[lane]
int16x4_t vmul_n_s16(int16x4_t a, int16_t b);                // MUL Vd.4H,Vn.4H,Vm.H[0]
int16x8_t vmulq_n_s16(int16x8_t a, int16_t b);               // MUL Vd.8H,Vn.8H,Vm.H[0]
int32x2_t vmul_n_s32(int32x2_t a, int32_t b);                // MUL Vd.2S,Vn.2S,Vm.S[0]
int32x4_t vmulq_n_s32(int32x4_t a, int32_t b);               // MUL Vd.4S,Vn.4S,Vm.S[0]
uint16x4_t vmul_n_u16(uint16x4_t a, uint16_t b);             // MUL Vd.4H,Vn.4H,Vm.H[0]
uint16x8_t vmulq_n_u16(uint16x8_t a, uint16_t b);            // MUL Vd.8H,Vn.8H,Vm.H[0]
uint32x2_t vmul_n_u32(uint32x2_t a, uint32_t b);             // MUL Vd.2S,Vn.2S,Vm.S[0]
uint32x4_t vmulq_n_u32(uint32x4_t a, uint32_t b);            // MUL Vd.4S,Vn.4S,Vm.S[0]
float32x2_t vmul_n_f32(float32x2_t a, float32_t b);          // FMUL Vd.2S,Vn.2S,Vm.S[0]
float32x4_t vmulq_n_f32(float32x4_t a, float32_t b);         // FMUL Vd.4S,Vn.4S,Vm.S[0]
float64x1_t vmul_n_f64(float64x1_t a, float64_t b);          // FMUL Dd,Dn,Vm.D[0]
float64x2_t vmulq_n_f64(float64x2_t a, float64_t b);         // FMUL Vd.2D,Vn.2D,Vm.D[0]
int16x4_t vmul_lane_s16(int16x4_t a, int16x4_t v, const int lane);     // MUL Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vmulq_lane_s16(int16x8_t a, int16x4_t v, const int lane);    // MUL Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vmul_lane_s32(int32x2_t a, int32x2_t v, const int lane);     // MUL Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vmulq_lane_s32(int32x4_t a, int32x2_t v, const int lane);    // MUL Vd.4S,Vn.4S,Vm.S[lane]
uint16x4_t vmul_lane_u16(uint16x4_t a, uint16x4_t v, const int lane);  // MUL Vd.4H,Vn.4H,Vm.H[lane]
uint16x8_t vmulq_lane_u16(
    uint16x8_t a, uint16x4_t v, const int lane);                       // MUL Vd.8H,Vn.8H,Vm.H[lane]
uint32x2_t vmul_lane_u32(uint32x2_t a, uint32x2_t v, const int lane);  // MUL Vd.2S,Vn.2S,Vm.S[lane]
uint32x4_t vmulq_lane_u32(
    uint32x4_t a, uint32x2_t v, const int lane);  // MUL Vd.4S,Vn.4S,Vm.S[lane]
float32x2_t vmul_lane_f32(
    float32x2_t a, float32x2_t v, const int lane);  // FMUL Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vmulq_lane_f32(
    float32x4_t a, float32x2_t v, const int lane);  // FMUL Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vmul_lane_f64(float64x1_t a, float64x1_t v, const int lane);  // FMUL Dd,Dn,Vm.D[lane]
float64x2_t vmulq_lane_f64(
    float64x2_t a, float64x1_t v, const int lane);  // FMUL Vd.2D,Vn.2D,Vm.D[lane]
float32_t vmuls_lane_f32(float32_t a, float32x2_t v, const int lane);  // FMUL Sd,Sn,Vm.S[lane]
float64_t vmuld_lane_f64(float64_t a, float64x1_t v, const int lane);  // FMUL Dd,Dn,Vm.S[lane]
int16x4_t vmul_laneq_s16(int16x4_t a, int16x8_t v, const int lane);    // MUL Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vmulq_laneq_s16(int16x8_t a, int16x8_t v, const int lane);   // MUL Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vmul_laneq_s32(int32x2_t a, int32x4_t v, const int lane);    // MUL Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vmulq_laneq_s32(int32x4_t a, int32x4_t v, const int lane);   // MUL Vd.4S,Vn.4S,Vm.S[lane]
uint16x4_t vmul_laneq_u16(
    uint16x4_t a, uint16x8_t v, const int lane);  // MUL Vd.4H,Vn.4H,Vm.H[lane]
uint16x8_t vmulq_laneq_u16(
    uint16x8_t a, uint16x8_t v, const int lane);  // MUL Vd.8H,Vn.8H,Vm.H[lane]
uint32x2_t vmul_laneq_u32(
    uint32x2_t a, uint32x4_t v, const int lane);  // MUL Vd.2S,Vn.2S,Vm.S[lane]
uint32x4_t vmulq_laneq_u32(
    uint32x4_t a, uint32x4_t v, const int lane);  // MUL Vd.4S,Vn.4S,Vm.S[lane]
float32x2_t vmul_laneq_f32(
    float32x2_t a, float32x4_t v, const int lane);  // FMUL Vd.2S,Vn.2S,Vm.S[lane]
float32x4_t vmulq_laneq_f32(
    float32x4_t a, float32x4_t v, const int lane);  // FMUL Vd.4S,Vn.4S,Vm.S[lane]
float64x1_t vmul_laneq_f64(float64x1_t a, float64x2_t v, const int lane);  // FMUL Dd,Dn,Vm.D[lane]
float64x2_t vmulq_laneq_f64(
    float64x2_t a, float64x2_t v, const int lane);  // FMUL Vd.2D,Vn.2D,Vm.D[lane]
float32_t vmuls_laneq_f32(float32_t a, float32x4_t v, const int lane);  // FMUL Sd,Sn,Vm.S[lane]
float64_t vmuld_laneq_f64(float64_t a, float64x2_t v, const int lane);  // FMUL Dd,Dn,Vm.D[lane]
int32x4_t vmull_n_s16(int16x4_t a, int16_t b);                          // SMULL Vd.4S,Vn.4H,Vm.H[0]
int64x2_t vmull_n_s32(int32x2_t a, int32_t b);                          // SMULL Vd.2D,Vn.2S,Vm.S[0]
uint32x4_t vmull_n_u16(uint16x4_t a, uint16_t b);                       // UMULL Vd.4S,Vn.4H,Vm.H[0]
uint64x2_t vmull_n_u32(uint32x2_t a, uint32_t b);                       // UMULL Vd.2D,Vn.2S,Vm.S[0]
int32x4_t vmull_high_n_s16(int16x8_t a, int16_t b);                  // SMULL2 Vd.4S,Vn.8H,Vm.H[0]
int64x2_t vmull_high_n_s32(int32x4_t a, int32_t b);                  // SMULL2 Vd.2D,Vn.4S,Vm.S[0]
uint32x4_t vmull_high_n_u16(uint16x8_t a, uint16_t b);               // UMULL2 Vd.4S,Vn.8H,Vm.H[0]
uint64x2_t vmull_high_n_u32(uint32x4_t a, uint32_t b);               // UMULL2 Vd.2D,Vn.4S,Vm.S[0]
int32x4_t vmull_lane_s16(int16x4_t a, int16x4_t v, const int lane);  // SMULL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vmull_lane_s32(int32x2_t a, int32x2_t v, const int lane);  // SMULL Vd.2D,Vn.2S,Vm.S[lane]
uint32x4_t vmull_lane_u16(
    uint16x4_t a, uint16x4_t v, const int lane);  // UMULL Vd.4S,Vn.4H,Vm.H[lane]
uint64x2_t vmull_lane_u32(
    uint32x2_t a, uint32x2_t v, const int lane);  // UMULL Vd.2D,Vn.2S,Vm.S[lane]
int32x4_t vmull_high_lane_s16(
    int16x8_t a, int16x4_t v, const int lane);  // SMULL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vmull_high_lane_s32(
    int32x4_t a, int32x2_t v, const int lane);  // SMULL2 Vd.2D,Vn.4S,Vm.S[lane]
uint32x4_t vmull_high_lane_u16(
    uint16x8_t a, uint16x4_t v, const int lane);  // UMULL2 Vd.4S,Vn.8H,Vm.H[lane]
uint64x2_t vmull_high_lane_u32(
    uint32x4_t a, uint32x2_t v, const int lane);  // UMULL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vmull_laneq_s16(
    int16x4_t a, int16x8_t v, const int lane);  // SMULL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vmull_laneq_s32(
    int32x2_t a, int32x4_t v, const int lane);  // SMULL Vd.2D,Vn.2S,Vm.S[lane]
uint32x4_t vmull_laneq_u16(
    uint16x4_t a, uint16x8_t v, const int lane);  // UMULL Vd.4S,Vn.4H,Vm.H[lane]
uint64x2_t vmull_laneq_u32(
    uint32x2_t a, uint32x4_t v, const int lane);  // UMULL Vd.2D,Vn.2S,Vm.S[lane]
int32x4_t vmull_high_laneq_s16(
    int16x8_t a, int16x8_t v, const int lane);  // SMULL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vmull_high_laneq_s32(
    int32x4_t a, int32x4_t v, const int lane);  // SMULL2 Vd.2D,Vn.4S,Vm.S[lane]
uint32x4_t vmull_high_laneq_u16(
    uint16x8_t a, uint16x8_t v, const int lane);  // UMULL2 Vd.4S,Vn.8H,Vm.H[lane]
uint64x2_t vmull_high_laneq_u32(
    uint32x4_t a, uint32x4_t v, const int lane);       // UMULL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vqdmull_n_s16(int16x4_t a, int16_t b);       // SQDMULL Vd.4S,Vn.4H,Vm.H[0]
int64x2_t vqdmull_n_s32(int32x2_t a, int32_t b);       // SQDMULL Vd.2D,Vn.2S,Vm.S[0]
int32x4_t vqdmull_high_n_s16(int16x8_t a, int16_t b);  // SQDMULL2 Vd.4S,Vn.8H,Vm.H[0]
int64x2_t vqdmull_high_n_s32(int32x4_t a, int32_t b);  // SQDMULL2 Vd.2D,Vn.4S,Vm.S[0]
int32x4_t vqdmull_lane_s16(
    int16x4_t a, int16x4_t v, const int lane);  // SQDMULL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vqdmull_lane_s32(
    int32x2_t a, int32x2_t v, const int lane);  // SQDMULL Vd.2D,Vn.2S,Vm.S[lane]
int32_t vqdmullh_lane_s16(int16_t a, int16x4_t v, const int lane);  // SQDMULL Sd,Hn,Vm.H[lane]
int64_t vqdmulls_lane_s32(int32_t a, int32x2_t v, const int lane);  // SQDMULL Dd,Sn,Vm.S[lane]
int32x4_t vqdmull_high_lane_s16(
    int16x8_t a, int16x4_t v, const int lane);  // SQDMULL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vqdmull_high_lane_s32(
    int32x4_t a, int32x2_t v, const int lane);  // SQDMULL2 Vd.2D,Vn.4S,Vm.S[lane]
int32x4_t vqdmull_laneq_s16(
    int16x4_t a, int16x8_t v, const int lane);  // SQDMULL Vd.4S,Vn.4H,Vm.H[lane]
int64x2_t vqdmull_laneq_s32(
    int32x2_t a, int32x4_t v, const int lane);  // SQDMULL Vd.2D,Vn.2S,Vm.S[lane]
int32_t vqdmullh_laneq_s16(int16_t a, int16x8_t v, const int lane);  // SQDMULL Sd,Hn,Vm.H[lane]
int64_t vqdmulls_laneq_s32(int32_t a, int32x4_t v, const int lane);  // SQDMULL Dd,Sn,Vm.S[lane]
int32x4_t vqdmull_high_laneq_s16(
    int16x8_t a, int16x8_t v, const int lane);  // SQDMULL2 Vd.4S,Vn.8H,Vm.H[lane]
int64x2_t vqdmull_high_laneq_s32(
    int32x4_t a, int32x4_t v, const int lane);     // SQDMULL2 Vd.2D,Vn.4S,Vm.S[lane]
int16x4_t vqdmulh_n_s16(int16x4_t a, int16_t b);   // SQDMULH Vd.4H,Vn.4H,Vm.H[0]
int16x8_t vqdmulhq_n_s16(int16x8_t a, int16_t b);  // SQDMULH Vd.8H,Vn.8H,Vm.H[0]
int32x2_t vqdmulh_n_s32(int32x2_t a, int32_t b);   // SQDMULH Vd.2S,Vn.2S,Vm.S[0]
int32x4_t vqdmulhq_n_s32(int32x4_t a, int32_t b);  // SQDMULH Vd.4S,Vn.4S,Vm.S[0]
int16x4_t vqdmulh_lane_s16(
    int16x4_t a, int16x4_t v, const int lane);  // SQDMULH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqdmulhq_lane_s16(
    int16x8_t a, int16x4_t v, const int lane);  // SQDMULH Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vqdmulh_lane_s32(
    int32x2_t a, int32x2_t v, const int lane);  // SQDMULH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqdmulhq_lane_s32(
    int32x4_t a, int32x2_t v, const int lane);  // SQDMULH Vd.4S,Vn.4S,Vm.S[lane]
int16_t vqdmulhh_lane_s16(int16_t a, int16x4_t v, const int lane);  // SQDMULH Hd,Hn,Vm.H[lane]
int32_t vqdmulhs_lane_s32(int32_t a, int32x2_t v, const int lane);  // SQDMULH Sd,Sn,Vm.H[lane]
int16x4_t vqdmulh_laneq_s16(
    int16x4_t a, int16x8_t v, const int lane);  // SQDMULH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqdmulhq_laneq_s16(
    int16x8_t a, int16x8_t v, const int lane);  // SQDMULH Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vqdmulh_laneq_s32(
    int32x2_t a, int32x4_t v, const int lane);  // SQDMULH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqdmulhq_laneq_s32(
    int32x4_t a, int32x4_t v, const int lane);  // SQDMULH Vd.4S,Vn.4S,Vm.S[lane]
int16_t vqdmulhh_laneq_s16(int16_t a, int16x8_t v, const int lane);  // SQDMULH Hd,Hn,Vm.H[lane]
int32_t vqdmulhs_laneq_s32(int32_t a, int32x4_t v, const int lane);  // SQDMULH Sd,Sn,Vm.H[lane]
int16x4_t vqrdmulh_n_s16(int16x4_t a, int16_t b);                    // SQRDMULH Vd.4H,Vn.4H,Vm.H[0]
int16x8_t vqrdmulhq_n_s16(int16x8_t a, int16_t b);                   // SQRDMULH Vd.8H,Vn.8H,Vm.H[0]
int32x2_t vqrdmulh_n_s32(int32x2_t a, int32_t b);                    // SQRDMULH Vd.2S,Vn.2S,Vm.S[0]
int32x4_t vqrdmulhq_n_s32(int32x4_t a, int32_t b);                   // SQRDMULH Vd.4S,Vn.4S,Vm.S[0]
int16x4_t vqrdmulh_lane_s16(
    int16x4_t a, int16x4_t v, const int lane);  // SQRDMULH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqrdmulhq_lane_s16(
    int16x8_t a, int16x4_t v, const int lane);  // SQRDMULH Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vqrdmulh_lane_s32(
    int32x2_t a, int32x2_t v, const int lane);  // SQRDMULH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqrdmulhq_lane_s32(
    int32x4_t a, int32x2_t v, const int lane);  // SQRDMULH Vd.4S,Vn.4S,Vm.S[lane]
int16_t vqrdmulhh_lane_s16(int16_t a, int16x4_t v, const int lane);  // SQRDMULH Hd,Hn,Vm.H[lane]
int32_t vqrdmulhs_lane_s32(int32_t a, int32x2_t v, const int lane);  // SQRDMULH Sd,Sn,Vm.S[lane]
int16x4_t vqrdmulh_laneq_s16(
    int16x4_t a, int16x8_t v, const int lane);  // SQRDMULH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqrdmulhq_laneq_s16(
    int16x8_t a, int16x8_t v, const int lane);  // SQRDMULH Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vqrdmulh_laneq_s32(
    int32x2_t a, int32x4_t v, const int lane);  // SQRDMULH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqrdmulhq_laneq_s32(
    int32x4_t a, int32x4_t v, const int lane);  // SQRDMULH Vd.4S,Vn.4S,Vm.S[lane]
int16_t vqrdmulhh_laneq_s16(int16_t a, int16x8_t v, const int lane);  // SQRDMULH Hd,Hn,Vm.H[lane]
int32_t vqrdmulhs_laneq_s32(int32_t a, int32x4_t v, const int lane);  // SQRDMULH Sd,Sn,Vm.S[lane]
int16x4_t vmla_n_s16(int16x4_t a, int16x4_t b, int16_t c);            // MLA Vd.4H,Vn.4H,Vm.H[0]
int16x8_t vmlaq_n_s16(int16x8_t a, int16x8_t b, int16_t c);           // MLA Vd.8H,Vn.8H,Vm.H[0]
int32x2_t vmla_n_s32(int32x2_t a, int32x2_t b, int32_t c);            // MLA Vd.2S,Vn.2S,Vm.S[0]
int32x4_t vmlaq_n_s32(int32x4_t a, int32x4_t b, int32_t c);           // MLA Vd.4S,Vn.4S,Vm.S[0]
uint16x4_t vmla_n_u16(uint16x4_t a, uint16x4_t b, uint16_t c);        // MLA Vd.4H,Vn.4H,Vm.H[0]
uint16x8_t vmlaq_n_u16(uint16x8_t a, uint16x8_t b, uint16_t c);       // MLA Vd.8H,Vn.8H,Vm.H[0]
uint32x2_t vmla_n_u32(uint32x2_t a, uint32x2_t b, uint32_t c);        // MLA Vd.2S,Vn.2S,Vm.S[0]
uint32x4_t vmlaq_n_u32(uint32x4_t a, uint32x4_t b, uint32_t c);       // MLA Vd.4S,Vn.4S,Vm.S[0]
float32x2_t vmla_n_f32(
    float32x2_t a, float32x2_t b, float32_t c);  // RESULT[I] = a[i] + (b[i] * c) for i = 0 to 1
float32x4_t vmlaq_n_f32(
    float32x4_t a, float32x4_t b, float32_t c);  // RESULT[I] = a[i] + (b[i] * c) for i = 0 to 3
int32x4_t vmlal_n_s16(int32x4_t a, int16x4_t b, int16_t c);           // SMLAL Vd.4S,Vn.4H,Vm.H[0]
int64x2_t vmlal_n_s32(int64x2_t a, int32x2_t b, int32_t c);           // SMLAL Vd.2D,Vn.2S,Vm.S[0]
uint32x4_t vmlal_n_u16(uint32x4_t a, uint16x4_t b, uint16_t c);       // UMLAL Vd.4S,Vn.4H,Vm.H[0]
uint64x2_t vmlal_n_u32(uint64x2_t a, uint32x2_t b, uint32_t c);       // UMLAL Vd.2D,Vn.2S,Vm.S[0]
int32x4_t vmlal_high_n_s16(int32x4_t a, int16x8_t b, int16_t c);      // SMLAL2 Vd.4S,Vn.8H,Vm.H[0]
int64x2_t vmlal_high_n_s32(int64x2_t a, int32x4_t b, int32_t c);      // SMLAL2 Vd.2D,Vn.4S,Vm.S[0]
uint32x4_t vmlal_high_n_u16(uint32x4_t a, uint16x8_t b, uint16_t c);  // UMLAL2 Vd.4S,Vn.8H,Vm.H[0]
uint64x2_t vmlal_high_n_u32(uint64x2_t a, uint32x4_t b, uint32_t c);  // UMLAL2 Vd.2D,Vn.4S,Vm.S[0]
int32x4_t vqdmlal_n_s16(int32x4_t a, int16x4_t b, int16_t c);         // SQDMLAL Vd.4S,Vn.4H,Vm.H[0]
int64x2_t vqdmlal_n_s32(int64x2_t a, int32x2_t b, int32_t c);         // SQDMLAL Vd.2D,Vn.2S,Vm.S[0]
int32x4_t vqdmlal_high_n_s16(int32x4_t a, int16x8_t b, int16_t c);  // SQDMLAL2 Vd.4S,Vn.8H,Vm.H[0]
int64x2_t vqdmlal_high_n_s32(int64x2_t a, int32x4_t b, int32_t c);  // SQDMLAL2 Vd.2D,Vn.4S,Vm.S[0]
int16x4_t vmls_n_s16(int16x4_t a, int16x4_t b, int16_t c);          // MLS Vd.4H,Vn.4H,Vm.H[0]
int16x8_t vmlsq_n_s16(int16x8_t a, int16x8_t b, int16_t c);         // MLS Vd.8H,Vn.8H,Vm.H[0]
int32x2_t vmls_n_s32(int32x2_t a, int32x2_t b, int32_t c);          // MLS Vd.2S,Vn.2S,Vm.S[0]
int32x4_t vmlsq_n_s32(int32x4_t a, int32x4_t b, int32_t c);         // MLS Vd.4S,Vn.4S,Vm.S[0]
uint16x4_t vmls_n_u16(uint16x4_t a, uint16x4_t b, uint16_t c);      // MLS Vd.4H,Vn.4H,Vm.H[0]
uint16x8_t vmlsq_n_u16(uint16x8_t a, uint16x8_t b, uint16_t c);     // MLS Vd.8H,Vn.8H,Vm.H[0]
uint32x2_t vmls_n_u32(uint32x2_t a, uint32x2_t b, uint32_t c);      // MLS Vd.2S,Vn.2S,Vm.S[0]
uint32x4_t vmlsq_n_u32(uint32x4_t a, uint32x4_t b, uint32_t c);     // MLS Vd.4S,Vn.4S,Vm.S[0]
float32x2_t vmls_n_f32(
    float32x2_t a, float32x2_t b, float32_t c);  // RESULT[I] = a[i] - (b[i] * c) for i = 0 to 1
float32x4_t vmlsq_n_f32(
    float32x4_t a, float32x4_t b, float32_t c);  // RESULT[I] = a[i] - (b[i] * c) for i = 0 to 3
int32x4_t vmlsl_n_s16(int32x4_t a, int16x4_t b, int16_t c);           // SMLSL Vd.4S,Vn.4H,Vm.H[0]
int64x2_t vmlsl_n_s32(int64x2_t a, int32x2_t b, int32_t c);           // SMLSL Vd.2D,Vn.2S,Vm.S[0]
uint32x4_t vmlsl_n_u16(uint32x4_t a, uint16x4_t b, uint16_t c);       // UMLSL Vd.4S,Vn.4H,Vm.H[0]
uint64x2_t vmlsl_n_u32(uint64x2_t a, uint32x2_t b, uint32_t c);       // UMLSL Vd.2D,Vn.2S,Vm.S[0]
int32x4_t vmlsl_high_n_s16(int32x4_t a, int16x8_t b, int16_t c);      // SMLSL2 Vd.4S,Vn.8H,Vm.H[0]
int64x2_t vmlsl_high_n_s32(int64x2_t a, int32x4_t b, int32_t c);      // SMLSL2 Vd.2D,Vn.4S,Vm.S[0]
uint32x4_t vmlsl_high_n_u16(uint32x4_t a, uint16x8_t b, uint16_t c);  // UMLSL2 Vd.4S,Vn.8H,Vm.H[0]
uint64x2_t vmlsl_high_n_u32(uint64x2_t a, uint32x4_t b, uint32_t c);  // UMLSL2 Vd.2D,Vn.4S,Vm.S[0]
int32x4_t vqdmlsl_n_s16(int32x4_t a, int16x4_t b, int16_t c);         // SQDMLSL Vd.4S,Vn.4H,Vm.H[0]
int64x2_t vqdmlsl_n_s32(int64x2_t a, int32x2_t b, int32_t c);         // SQDMLSL Vd.2D,Vn.2S,Vm.S[0]
int32x4_t vqdmlsl_high_n_s16(int32x4_t a, int16x8_t b, int16_t c);  // SQDMLSL2 Vd.4S,Vn.8H,Vm.H[0]
int64x2_t vqdmlsl_high_n_s32(int64x2_t a, int32x4_t b, int32_t c);  // SQDMLSL2 Vd.2D,Vn.4S,Vm.S[0]
int8x8_t vabs_s8(int8x8_t a);                                       // ABS Vd.8B,Vn.8B
int8x16_t vabsq_s8(int8x16_t a);                                    // ABS Vd.16B,Vn.16B
int16x4_t vabs_s16(int16x4_t a);                                    // ABS Vd.4H,Vn.4H
int16x8_t vabsq_s16(int16x8_t a);                                   // ABS Vd.8H,Vn.8H
int32x2_t vabs_s32(int32x2_t a);                                    // ABS Vd.2S,Vn.2S
int32x4_t vabsq_s32(int32x4_t a);                                   // ABS Vd.4S,Vn.4S
float32x2_t vabs_f32(float32x2_t a);                                // FABS Vd.2S,Vn.2S
float32x4_t vabsq_f32(float32x4_t a);                               // FABS Vd.4S,Vn.4S
int64x1_t vabs_s64(int64x1_t a);                                    // ABS Dd,Dn
int64_t vabsd_s64(int64_t a);                                       // ABS Dd,Dn
int64x2_t vabsq_s64(int64x2_t a);                                   // ABS Vd.2D,Vn.2D
float64x1_t vabs_f64(float64x1_t a);                                // FABS Dd,Dn
float64x2_t vabsq_f64(float64x2_t a);                               // FABS Vd.2D,Vn.2D
int8x8_t vqabs_s8(int8x8_t a);                                      // SQABS Vd.8B,Vn.8B
int8x16_t vqabsq_s8(int8x16_t a);                                   // SQABS Vd.16B,Vn.16B
int16x4_t vqabs_s16(int16x4_t a);                                   // SQABS Vd.4H,Vn.4H
int16x8_t vqabsq_s16(int16x8_t a);                                  // SQABS Vd.8H,Vn.8H
int32x2_t vqabs_s32(int32x2_t a);                                   // SQABS Vd.2S,Vn.2S
int32x4_t vqabsq_s32(int32x4_t a);                                  // SQABS Vd.4S,Vn.4S
int64x1_t vqabs_s64(int64x1_t a);                                   // SQABS Dd,Dn
int64x2_t vqabsq_s64(int64x2_t a);                                  // SQABS Vd.2D,Vn.2D
int8_t vqabsb_s8(int8_t a);                                         // SQABS Bd,Bn
int16_t vqabsh_s16(int16_t a);                                      // SQABS Hd,Hn
int32_t vqabss_s32(int32_t a);                                      // SQABS Sd,Sn
int64_t vqabsd_s64(int64_t a);                                      // SQABS Dd,Dn
int8x8_t vneg_s8(int8x8_t a);                                       // NEG Vd.8B,Vn.8B
int8x16_t vnegq_s8(int8x16_t a);                                    // NEG Vd.16B,Vn.16B
int16x4_t vneg_s16(int16x4_t a);                                    // NEG Vd.4H,Vn.4H
int16x8_t vnegq_s16(int16x8_t a);                                   // NEG Vd.8H,Vn.8H
int32x2_t vneg_s32(int32x2_t a);                                    // NEG Vd.2S,Vn.2S
int32x4_t vnegq_s32(int32x4_t a);                                   // NEG Vd.4S,Vn.4S
float32x2_t vneg_f32(float32x2_t a);                                // FNEG Vd.2S,Vn.2S
float32x4_t vnegq_f32(float32x4_t a);                               // FNEG Vd.4S,Vn.4S
int64x1_t vneg_s64(int64x1_t a);                                    // NEG Dd,Dn
int64_t vnegd_s64(int64_t a);                                       // NEG Dd,Dn
int64x2_t vnegq_s64(int64x2_t a);                                   // NEG Vd.2D,Vn.2D
float64x1_t vneg_f64(float64x1_t a);                                // FNEG Dd,Dn
float64x2_t vnegq_f64(float64x2_t a);                               // FNEG Vd.2D,Vn.2D
int8x8_t vqneg_s8(int8x8_t a);                                      // SQNEG Vd.8B,Vn.8B
int8x16_t vqnegq_s8(int8x16_t a);                                   // SQNEG Vd.16B,Vn.16B
int16x4_t vqneg_s16(int16x4_t a);                                   // SQNEG Vd.4H,Vn.4H
int16x8_t vqnegq_s16(int16x8_t a);                                  // SQNEG Vd.8H,Vn.8H
int32x2_t vqneg_s32(int32x2_t a);                                   // SQNEG Vd.2S,Vn.2S
int32x4_t vqnegq_s32(int32x4_t a);                                  // SQNEG Vd.4S,Vn.4S
int64x1_t vqneg_s64(int64x1_t a);                                   // SQNEG Dd,Dn
int64x2_t vqnegq_s64(int64x2_t a);                                  // SQNEG Vd.2D,Vn.2D
int8_t vqnegb_s8(int8_t a);                                         // SQNEG Bd,Bn
int16_t vqnegh_s16(int16_t a);                                      // SQNEG Hd,Hn
int32_t vqnegs_s32(int32_t a);                                      // SQNEG Sd,Sn
int64_t vqnegd_s64(int64_t a);                                      // SQNEG Dd,Dn
int8x8_t vcls_s8(int8x8_t a);                                       // CLS Vd.8B,Vn.8B
int8x16_t vclsq_s8(int8x16_t a);                                    // CLS Vd.16B,Vn.16B
int16x4_t vcls_s16(int16x4_t a);                                    // CLS Vd.4H,Vn.4H
int16x8_t vclsq_s16(int16x8_t a);                                   // CLS Vd.8H,Vn.8H
int32x2_t vcls_s32(int32x2_t a);                                    // CLS Vd.2S,Vn.2S
int32x4_t vclsq_s32(int32x4_t a);                                   // CLS Vd.4S,Vn.4S
int8x8_t vcls_u8(uint8x8_t a);                                      // CLS Vd.8B,Vn.8B
int8x16_t vclsq_u8(uint8x16_t a);                                   // CLS Vd.16B,Vn.16B
int16x4_t vcls_u16(uint16x4_t a);                                   // CLS Vd.4H,Vn.4H
int16x8_t vclsq_u16(uint16x8_t a);                                  // CLS Vd.8H,Vn.8H
int32x2_t vcls_u32(uint32x2_t a);                                   // CLS Vd.2S,Vn.2S
int32x4_t vclsq_u32(uint32x4_t a);                                  // CLS Vd.4S,Vn.4S
int8x8_t vclz_s8(int8x8_t a);                                       // CLZ Vd.8B,Vn.8B
int8x16_t vclzq_s8(int8x16_t a);                                    // CLZ Vd.16B,Vn.16B
int16x4_t vclz_s16(int16x4_t a);                                    // CLZ Vd.4H,Vn.4H
int16x8_t vclzq_s16(int16x8_t a);                                   // CLZ Vd.8H,Vn.8H
int32x2_t vclz_s32(int32x2_t a);                                    // CLZ Vd.2S,Vn.2S
int32x4_t vclzq_s32(int32x4_t a);                                   // CLZ Vd.4S,Vn.4S
uint8x8_t vclz_u8(uint8x8_t a);                                     // CLZ Vd.8B,Vn.8B
uint8x16_t vclzq_u8(uint8x16_t a);                                  // CLZ Vd.16B,Vn.16B
uint16x4_t vclz_u16(uint16x4_t a);                                  // CLZ Vd.4H,Vn.4H
uint16x8_t vclzq_u16(uint16x8_t a);                                 // CLZ Vd.8H,Vn.8H
uint32x2_t vclz_u32(uint32x2_t a);                                  // CLZ Vd.2S,Vn.2S
uint32x4_t vclzq_u32(uint32x4_t a);                                 // CLZ Vd.4S,Vn.4S
int8x8_t vcnt_s8(int8x8_t a);                                       // CNT Vd.8B,Vn.8B
int8x16_t vcntq_s8(int8x16_t a);                                    // CNT Vd.16B,Vn.16B
uint8x8_t vcnt_u8(uint8x8_t a);                                     // CNT Vd.8B,Vn.8B
uint8x16_t vcntq_u8(uint8x16_t a);                                  // CNT Vd.16B,Vn.16B
poly8x8_t vcnt_p8(poly8x8_t a);                                     // CNT Vd.8B,Vn.8B
poly8x16_t vcntq_p8(poly8x16_t a);                                  // CNT Vd.16B,Vn.16B
uint32x2_t vrecpe_u32(uint32x2_t a);                                // URECPE Vd.2S,Vn.2S
uint32x4_t vrecpeq_u32(uint32x4_t a);                               // URECPE Vd.4S,Vn.4S
float32x2_t vrecpe_f32(float32x2_t a);                              // FRECPE Vd.2S,Vn.2S
float32x4_t vrecpeq_f32(float32x4_t a);                             // FRECPE Vd.4S,Vn.4S
float64x1_t vrecpe_f64(float64x1_t a);                              // FRECPE Dd,Dn
float64x2_t vrecpeq_f64(float64x2_t a);                             // FRECPE Vd.2D,Vn.2D
float32_t vrecpes_f32(float32_t a);                                 // FRECPE Sd,Sn
float64_t vrecped_f64(float64_t a);                                 // FRECPE Dd,Dn
float32x2_t vrecps_f32(float32x2_t a, float32x2_t b);               // FRECPS Vd.2S,Vn.2S,Vm.2S
float32x4_t vrecpsq_f32(float32x4_t a, float32x4_t b);              // FRECPS Vd.4S,Vn.4S,Vm.4S
float64x1_t vrecps_f64(float64x1_t a, float64x1_t b);               // FRECPS Dd,Dn,Dm
float64x2_t vrecpsq_f64(float64x2_t a, float64x2_t b);              // FRECPS Vd.2D,Vn.2D,Vm.2D
float32_t vrecpss_f32(float32_t a, float32_t b);                    // FRECPS Sd,Sn,Sm
float64_t vrecpsd_f64(float64_t a, float64_t b);                    // FRECPS Dd,Dn,Dm
float32x2_t vsqrt_f32(float32x2_t a);                               // FSQRT Vd.2S,Vn.2S
float32x4_t vsqrtq_f32(float32x4_t a);                              // FSQRT Vd.4S,Vn.4S
float64x1_t vsqrt_f64(float64x1_t a);                               // FSQRT Dd,Dn
float64x2_t vsqrtq_f64(float64x2_t a);                              // FSQRT Vd.2D,Vn.2D
uint32x2_t vrsqrte_u32(uint32x2_t a);                               // URSQRTE Vd.2S,Vn.2S
uint32x4_t vrsqrteq_u32(uint32x4_t a);                              // URSQRTE Vd.4S,Vn.4S
float32x2_t vrsqrte_f32(float32x2_t a);                             // FRSQRTE Vd.2S,Vn.2S
float32x4_t vrsqrteq_f32(float32x4_t a);                            // FRSQRTE Vd.4S,Vn.4S
float64x1_t vrsqrte_f64(float64x1_t a);                             // FRSQRTE Dd,Dn
float64x2_t vrsqrteq_f64(float64x2_t a);                            // FRSQRTE Vd.2D,Vn.2D
float32_t vrsqrtes_f32(float32_t a);                                // FRSQRTE Sd,Sn
float64_t vrsqrted_f64(float64_t a);                                // FRSQRTE Dd,Dn
float32x2_t vrsqrts_f32(float32x2_t a, float32x2_t b);              // FRSQRTS Vd.2S,Vn.2S,Vm.2S
float32x4_t vrsqrtsq_f32(float32x4_t a, float32x4_t b);             // FRSQRTS Vd.4S,Vn.4S,Vm.4S
float64x1_t vrsqrts_f64(float64x1_t a, float64x1_t b);              // FRSQRTS Dd,Dn,Dm
float64x2_t vrsqrtsq_f64(float64x2_t a, float64x2_t b);             // FRSQRTS Vd.2D,Vn.2D,Vm.2D
float32_t vrsqrtss_f32(float32_t a, float32_t b);                   // FRSQRTS Sd,Sn,Sm
float64_t vrsqrtsd_f64(float64_t a, float64_t b);                   // FRSQRTS Dd,Dn,Dm
int8x8_t vmvn_s8(int8x8_t a);                                       // MVN Vd.8B,Vn.8B
int8x16_t vmvnq_s8(int8x16_t a);                                    // MVN Vd.16B,Vn.16B
int16x4_t vmvn_s16(int16x4_t a);                                    // MVN Vd.8B,Vn.8B
int16x8_t vmvnq_s16(int16x8_t a);                                   // MVN Vd.16B,Vn.16B
int32x2_t vmvn_s32(int32x2_t a);                                    // MVN Vd.8B,Vn.8B
int32x4_t vmvnq_s32(int32x4_t a);                                   // MVN Vd.16B,Vn.16B
uint8x8_t vmvn_u8(uint8x8_t a);                                     // MVN Vd.8B,Vn.8B
uint8x16_t vmvnq_u8(uint8x16_t a);                                  // MVN Vd.16B,Vn.16B
uint16x4_t vmvn_u16(uint16x4_t a);                                  // MVN Vd.8B,Vn.8B
uint16x8_t vmvnq_u16(uint16x8_t a);                                 // MVN Vd.16B,Vn.16B
uint32x2_t vmvn_u32(uint32x2_t a);                                  // MVN Vd.8B,Vn.8B
uint32x4_t vmvnq_u32(uint32x4_t a);                                 // MVN Vd.16B,Vn.16B
poly8x8_t vmvn_p8(poly8x8_t a);                                     // MVN Vd.8B,Vn.8B
poly8x16_t vmvnq_p8(poly8x16_t a);                                  // MVN Vd.16B,Vn.16B
int8x8_t vand_s8(int8x8_t a, int8x8_t b);                           // AND Vd.8B,Vn.8B,Vm.8B
int8x16_t vandq_s8(int8x16_t a, int8x16_t b);                       // AND Vd.16B,Vn.16B,Vm.16B
int16x4_t vand_s16(int16x4_t a, int16x4_t b);                       // AND Vd.8B,Vn.8B,Vm.8B
int16x8_t vandq_s16(int16x8_t a, int16x8_t b);                      // AND Vd.16B,Vn.16B,Vm.16B
int32x2_t vand_s32(int32x2_t a, int32x2_t b);                       // AND Vd.8B,Vn.8B,Vm.8B
int32x4_t vandq_s32(int32x4_t a, int32x4_t b);                      // AND Vd.16B,Vn.16B,Vm.16B
int64x1_t vand_s64(int64x1_t a, int64x1_t b);                       // AND Dd,Dn,Dm
int64x2_t vandq_s64(int64x2_t a, int64x2_t b);                      // AND Vd.16B,Vn.16B,Vm.16B
uint8x8_t vand_u8(uint8x8_t a, uint8x8_t b);                        // AND Vd.8B,Vn.8B,Vm.8B
uint8x16_t vandq_u8(uint8x16_t a, uint8x16_t b);                    // AND Vd.16B,Vn.16B,Vm.16B
uint16x4_t vand_u16(uint16x4_t a, uint16x4_t b);                    // AND Vd.8B,Vn.8B,Vm.8B
uint16x8_t vandq_u16(uint16x8_t a, uint16x8_t b);                   // AND Vd.16B,Vn.16B,Vm.16B
uint32x2_t vand_u32(uint32x2_t a, uint32x2_t b);                    // AND Vd.8B,Vn.8B,Vm.8B
uint32x4_t vandq_u32(uint32x4_t a, uint32x4_t b);                   // AND Vd.16B,Vn.16B,Vm.16B
uint64x1_t vand_u64(uint64x1_t a, uint64x1_t b);                    // AND Vd.8B,Vn.8B,Vm.8B
uint64x2_t vandq_u64(uint64x2_t a, uint64x2_t b);                   // AND Vd.16B,Vn.16B,Vm.16B
int8x8_t vorr_s8(int8x8_t a, int8x8_t b);                           // ORR Vd.8B,Vn.8B,Vm.8B
int8x16_t vorrq_s8(int8x16_t a, int8x16_t b);                       // ORR Vd.16B,Vn.16B,Vm.16B
int16x4_t vorr_s16(int16x4_t a, int16x4_t b);                       // ORR Vd.8B,Vn.8B,Vm.8B
int16x8_t vorrq_s16(int16x8_t a, int16x8_t b);                      // ORR Vd.16B,Vn.16B,Vm.16B
int32x2_t vorr_s32(int32x2_t a, int32x2_t b);                       // ORR Vd.8B,Vn.8B,Vm.8B
int32x4_t vorrq_s32(int32x4_t a, int32x4_t b);                      // ORR Vd.16B,Vn.16B,Vm.16B
int64x1_t vorr_s64(int64x1_t a, int64x1_t b);                       // ORR Vd.8B,Vn.8B,Vm.8B
int64x2_t vorrq_s64(int64x2_t a, int64x2_t b);                      // ORR Vd.16B,Vn.16B,Vm.16B
uint8x8_t vorr_u8(uint8x8_t a, uint8x8_t b);                        // ORR Vd.8B,Vn.8B,Vm.8B
uint8x16_t vorrq_u8(uint8x16_t a, uint8x16_t b);                    // ORR Vd.16B,Vn.16B,Vm.16B
uint16x4_t vorr_u16(uint16x4_t a, uint16x4_t b);                    // ORR Vd.8B,Vn.8B,Vm.8B
uint16x8_t vorrq_u16(uint16x8_t a, uint16x8_t b);                   // ORR Vd.16B,Vn.16B,Vm.16B
uint32x2_t vorr_u32(uint32x2_t a, uint32x2_t b);                    // ORR Vd.8B,Vn.8B,Vm.8B
uint32x4_t vorrq_u32(uint32x4_t a, uint32x4_t b);                   // ORR Vd.16B,Vn.16B,Vm.16B
uint64x1_t vorr_u64(uint64x1_t a, uint64x1_t b);                    // ORR Vd.8B,Vn.8B,Vm.8B
uint64x2_t vorrq_u64(uint64x2_t a, uint64x2_t b);                   // ORR Vd.16B,Vn.16B,Vm.16B
int8x8_t veor_s8(int8x8_t a, int8x8_t b);                           // EOR Vd.8B,Vn.8B,Vm.8B
int8x16_t veorq_s8(int8x16_t a, int8x16_t b);                       // EOR Vd.16B,Vn.16B,Vm.16B
int16x4_t veor_s16(int16x4_t a, int16x4_t b);                       // EOR Vd.8B,Vn.8B,Vm.8B
int16x8_t veorq_s16(int16x8_t a, int16x8_t b);                      // EOR Vd.16B,Vn.16B,Vm.16B
int32x2_t veor_s32(int32x2_t a, int32x2_t b);                       // EOR Vd.8B,Vn.8B,Vm.8B
int32x4_t veorq_s32(int32x4_t a, int32x4_t b);                      // EOR Vd.16B,Vn.16B,Vm.16B
int64x1_t veor_s64(int64x1_t a, int64x1_t b);                       // EOR Vd.8B,Vn.8B,Vm.8B
int64x2_t veorq_s64(int64x2_t a, int64x2_t b);                      // EOR Vd.16B,Vn.16B,Vm.16B
uint8x8_t veor_u8(uint8x8_t a, uint8x8_t b);                        // EOR Vd.8B,Vn.8B,Vm.8B
uint8x16_t veorq_u8(uint8x16_t a, uint8x16_t b);                    // EOR Vd.16B,Vn.16B,Vm.16B
uint16x4_t veor_u16(uint16x4_t a, uint16x4_t b);                    // EOR Vd.8B,Vn.8B,Vm.8B
uint16x8_t veorq_u16(uint16x8_t a, uint16x8_t b);                   // EOR Vd.16B,Vn.16B,Vm.16B
uint32x2_t veor_u32(uint32x2_t a, uint32x2_t b);                    // EOR Vd.8B,Vn.8B,Vm.8B
uint32x4_t veorq_u32(uint32x4_t a, uint32x4_t b);                   // EOR Vd.16B,Vn.16B,Vm.16B
uint64x1_t veor_u64(uint64x1_t a, uint64x1_t b);                    // EOR Vd.8B,Vn.8B,Vm.8B
uint64x2_t veorq_u64(uint64x2_t a, uint64x2_t b);                   // EOR Vd.16B,Vn.16B,Vm.16B
int8x8_t vbic_s8(int8x8_t a, int8x8_t b);                           // BIC Vd.8B,Vn.8B,Vm.8B
int8x16_t vbicq_s8(int8x16_t a, int8x16_t b);                       // BIC Vd.16B,Vn.16B,Vm.16B
int16x4_t vbic_s16(int16x4_t a, int16x4_t b);                       // BIC Vd.8B,Vn.8B,Vm.8B
int16x8_t vbicq_s16(int16x8_t a, int16x8_t b);                      // BIC Vd.16B,Vn.16B,Vm.16B
int32x2_t vbic_s32(int32x2_t a, int32x2_t b);                       // BIC Vd.8B,Vn.8B,Vm.8B
int32x4_t vbicq_s32(int32x4_t a, int32x4_t b);                      // BIC Vd.16B,Vn.16B,Vm.16B
int64x1_t vbic_s64(int64x1_t a, int64x1_t b);                       // BIC Vd.8B,Vn.8B,Vm.8B
int64x2_t vbicq_s64(int64x2_t a, int64x2_t b);                      // BIC Vd.16B,Vn.16B,Vm.16B
uint8x8_t vbic_u8(uint8x8_t a, uint8x8_t b);                        // BIC Vd.8B,Vn.8B,Vm.8B
uint8x16_t vbicq_u8(uint8x16_t a, uint8x16_t b);                    // BIC Vd.16B,Vn.16B,Vm.16B
uint16x4_t vbic_u16(uint16x4_t a, uint16x4_t b);                    // BIC Vd.8B,Vn.8B,Vm.8B
uint16x8_t vbicq_u16(uint16x8_t a, uint16x8_t b);                   // BIC Vd.16B,Vn.16B,Vm.16B
uint32x2_t vbic_u32(uint32x2_t a, uint32x2_t b);                    // BIC Vd.8B,Vn.8B,Vm.8B
uint32x4_t vbicq_u32(uint32x4_t a, uint32x4_t b);                   // BIC Vd.16B,Vn.16B,Vm.16B
uint64x1_t vbic_u64(uint64x1_t a, uint64x1_t b);                    // BIC Vd.8B,Vn.8B,Vm.8B
uint64x2_t vbicq_u64(uint64x2_t a, uint64x2_t b);                   // BIC Vd.16B,Vn.16B,Vm.16B
int8x8_t vorn_s8(int8x8_t a, int8x8_t b);                           // ORN Vd.8B,Vn.8B,Vm.8B
int8x16_t vornq_s8(int8x16_t a, int8x16_t b);                       // ORN Vd.16B,Vn.16B,Vm.16B
int16x4_t vorn_s16(int16x4_t a, int16x4_t b);                       // ORN Vd.8B,Vn.8B,Vm.8B
int16x8_t vornq_s16(int16x8_t a, int16x8_t b);                      // ORN Vd.16B,Vn.16B,Vm.16B
int32x2_t vorn_s32(int32x2_t a, int32x2_t b);                       // ORN Vd.8B,Vn.8B,Vm.8B
int32x4_t vornq_s32(int32x4_t a, int32x4_t b);                      // ORN Vd.16B,Vn.16B,Vm.16B
int64x1_t vorn_s64(int64x1_t a, int64x1_t b);                       // ORN Vd.8B,Vn.8B,Vm.8B
int64x2_t vornq_s64(int64x2_t a, int64x2_t b);                      // ORN Vd.16B,Vn.16B,Vm.16B
uint8x8_t vorn_u8(uint8x8_t a, uint8x8_t b);                        // ORN Vd.8B,Vn.8B,Vm.8B
uint8x16_t vornq_u8(uint8x16_t a, uint8x16_t b);                    // ORN Vd.16B,Vn.16B,Vm.16B
uint16x4_t vorn_u16(uint16x4_t a, uint16x4_t b);                    // ORN Vd.8B,Vn.8B,Vm.8B
uint16x8_t vornq_u16(uint16x8_t a, uint16x8_t b);                   // ORN Vd.16B,Vn.16B,Vm.16B
uint32x2_t vorn_u32(uint32x2_t a, uint32x2_t b);                    // ORN Vd.8B,Vn.8B,Vm.8B
uint32x4_t vornq_u32(uint32x4_t a, uint32x4_t b);                   // ORN Vd.16B,Vn.16B,Vm.16B
uint64x1_t vorn_u64(uint64x1_t a, uint64x1_t b);                    // ORN Vd.8B,Vn.8B,Vm.8B
uint64x2_t vornq_u64(uint64x2_t a, uint64x2_t b);                   // ORN Vd.16B,Vn.16B,Vm.16B
int8x8_t vbsl_s8(uint8x8_t a, int8x8_t b, int8x8_t c);              // BSL Vd.8B,Vn.8B,Vm.8B
int8x16_t vbslq_s8(uint8x16_t a, int8x16_t b, int8x16_t c);         // BSL Vd.16B,Vn.16B,Vm.16B
int16x4_t vbsl_s16(uint16x4_t a, int16x4_t b, int16x4_t c);         // BSL Vd.8B,Vn.8B,Vm.8B
int16x8_t vbslq_s16(uint16x8_t a, int16x8_t b, int16x8_t c);        // BSL Vd.16B,Vn.16B,Vm.16B
int32x2_t vbsl_s32(uint32x2_t a, int32x2_t b, int32x2_t c);         // BSL Vd.8B,Vn.8B,Vm.8B
int32x4_t vbslq_s32(uint32x4_t a, int32x4_t b, int32x4_t c);        // BSL Vd.16B,Vn.16B,Vm.16B
int64x1_t vbsl_s64(uint64x1_t a, int64x1_t b, int64x1_t c);         // BSL Vd.8B,Vn.8B,Vm.8B
int64x2_t vbslq_s64(uint64x2_t a, int64x2_t b, int64x2_t c);        // BSL Vd.16B,Vn.16B,Vm.16B
uint8x8_t vbsl_u8(uint8x8_t a, uint8x8_t b, uint8x8_t c);           // BSL Vd.8B,Vn.8B,Vm.8B
uint8x16_t vbslq_u8(uint8x16_t a, uint8x16_t b, uint8x16_t c);      // BSL Vd.16B,Vn.16B,Vm.16B
uint16x4_t vbsl_u16(uint16x4_t a, uint16x4_t b, uint16x4_t c);      // BSL Vd.8B,Vn.8B,Vm.8B
uint16x8_t vbslq_u16(uint16x8_t a, uint16x8_t b, uint16x8_t c);     // BSL Vd.16B,Vn.16B,Vm.16B
uint32x2_t vbsl_u32(uint32x2_t a, uint32x2_t b, uint32x2_t c);      // BSL Vd.8B,Vn.8B,Vm.8B
uint32x4_t vbslq_u32(uint32x4_t a, uint32x4_t b, uint32x4_t c);     // BSL Vd.16B,Vn.16B,Vm.16B
uint64x1_t vbsl_u64(uint64x1_t a, uint64x1_t b, uint64x1_t c);      // BSL Vd.8B,Vn.8B,Vm.8B
uint64x2_t vbslq_u64(uint64x2_t a, uint64x2_t b, uint64x2_t c);     // BSL Vd.16B,Vn.16B,Vm.16B
poly64x1_t vbsl_p64(poly64x1_t a, poly64x1_t b, poly64x1_t c);      // BSL Vd.8B,Vn.8B,Vm.8B
poly64x2_t vbslq_p64(poly64x2_t a, poly64x2_t b, poly64x2_t c);     // BSL Vd.16B,Vn.16B,Vm.16B
float32x2_t vbsl_f32(uint32x2_t a, float32x2_t b, float32x2_t c);   // BSL Vd.8B,Vn.8B,Vm.8B
float32x4_t vbslq_f32(uint32x4_t a, float32x4_t b, float32x4_t c);  // BSL Vd.16B,Vn.16B,Vm.16B
poly8x8_t vbsl_p8(uint8x8_t a, poly8x8_t b, poly8x8_t c);           // BSL Vd.8B,Vn.8B,Vm.8B
poly8x16_t vbslq_p8(uint8x16_t a, poly8x16_t b, poly8x16_t c);      // BSL Vd.16B,Vn.16B,Vm.16B
poly16x4_t vbsl_p16(uint16x4_t a, poly16x4_t b, poly16x4_t c);      // BSL Vd.8B,Vn.8B,Vm.8B
poly16x8_t vbslq_p16(uint16x8_t a, poly16x8_t b, poly16x8_t c);     // BSL Vd.16B,Vn.16B,Vm.16B
float64x1_t vbsl_f64(uint64x1_t a, float64x1_t b, float64x1_t c);   // BSL Vd.8B,Vn.8B,Vm.8B
float64x2_t vbslq_f64(uint64x2_t a, float64x2_t b, float64x2_t c);  // BSL Vd.16B,Vn.16B,Vm.16B
int8x8_t vcopy_lane_s8(
    int8x8_t a, const int lane1, int8x8_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
int8x16_t vcopyq_lane_s8(
    int8x16_t a, const int lane1, int8x8_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
int16x4_t vcopy_lane_s16(
    int16x4_t a, const int lane1, int16x4_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
int16x8_t vcopyq_lane_s16(
    int16x8_t a, const int lane1, int16x4_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
int32x2_t vcopy_lane_s32(
    int32x2_t a, const int lane1, int32x2_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
int32x4_t vcopyq_lane_s32(
    int32x4_t a, const int lane1, int32x2_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
int64x1_t vcopy_lane_s64(
    int64x1_t a, const int lane1, int64x1_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
int64x2_t vcopyq_lane_s64(
    int64x2_t a, const int lane1, int64x1_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
uint8x8_t vcopy_lane_u8(
    uint8x8_t a, const int lane1, uint8x8_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
uint8x16_t vcopyq_lane_u8(
    uint8x16_t a, const int lane1, uint8x8_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
uint16x4_t vcopy_lane_u16(
    uint16x4_t a, const int lane1, uint16x4_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
uint16x8_t vcopyq_lane_u16(
    uint16x8_t a, const int lane1, uint16x4_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
uint32x2_t vcopy_lane_u32(
    uint32x2_t a, const int lane1, uint32x2_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
uint32x4_t vcopyq_lane_u32(
    uint32x4_t a, const int lane1, uint32x2_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
uint64x1_t vcopy_lane_u64(
    uint64x1_t a, const int lane1, uint64x1_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
uint64x2_t vcopyq_lane_u64(
    uint64x2_t a, const int lane1, uint64x1_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
poly64x1_t vcopy_lane_p64(
    poly64x1_t a, const int lane1, poly64x1_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
poly64x2_t vcopyq_lane_p64(
    poly64x2_t a, const int lane1, poly64x1_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
float32x2_t vcopy_lane_f32(
    float32x2_t a, const int lane1, float32x2_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
float32x4_t vcopyq_lane_f32(
    float32x4_t a, const int lane1, float32x2_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
float64x1_t vcopy_lane_f64(
    float64x1_t a, const int lane1, float64x1_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
float64x2_t vcopyq_lane_f64(
    float64x2_t a, const int lane1, float64x1_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
poly8x8_t vcopy_lane_p8(
    poly8x8_t a, const int lane1, poly8x8_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
poly8x16_t vcopyq_lane_p8(
    poly8x16_t a, const int lane1, poly8x8_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
poly16x4_t vcopy_lane_p16(
    poly16x4_t a, const int lane1, poly16x4_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
poly16x8_t vcopyq_lane_p16(
    poly16x8_t a, const int lane1, poly16x4_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
int8x8_t vcopy_laneq_s8(
    int8x8_t a, const int lane1, int8x16_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
int8x16_t vcopyq_laneq_s8(
    int8x16_t a, const int lane1, int8x16_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
int16x4_t vcopy_laneq_s16(
    int16x4_t a, const int lane1, int16x8_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
int16x8_t vcopyq_laneq_s16(
    int16x8_t a, const int lane1, int16x8_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
int32x2_t vcopy_laneq_s32(
    int32x2_t a, const int lane1, int32x4_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
int32x4_t vcopyq_laneq_s32(
    int32x4_t a, const int lane1, int32x4_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
int64x1_t vcopy_laneq_s64(
    int64x1_t a, const int lane1, int64x2_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
int64x2_t vcopyq_laneq_s64(
    int64x2_t a, const int lane1, int64x2_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
uint8x8_t vcopy_laneq_u8(
    uint8x8_t a, const int lane1, uint8x16_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
uint8x16_t vcopyq_laneq_u8(
    uint8x16_t a, const int lane1, uint8x16_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
uint16x4_t vcopy_laneq_u16(
    uint16x4_t a, const int lane1, uint16x8_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
uint16x8_t vcopyq_laneq_u16(
    uint16x8_t a, const int lane1, uint16x8_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
uint32x2_t vcopy_laneq_u32(
    uint32x2_t a, const int lane1, uint32x4_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
uint32x4_t vcopyq_laneq_u32(
    uint32x4_t a, const int lane1, uint32x4_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
uint64x1_t vcopy_laneq_u64(
    uint64x1_t a, const int lane1, uint64x2_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
uint64x2_t vcopyq_laneq_u64(
    uint64x2_t a, const int lane1, uint64x2_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
poly64x1_t vcopy_laneq_p64(
    poly64x1_t a, const int lane1, poly64x2_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
poly64x2_t vcopyq_laneq_p64(
    poly64x2_t a, const int lane1, poly64x2_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
float32x2_t vcopy_laneq_f32(
    float32x2_t a, const int lane1, float32x4_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
float32x4_t vcopyq_laneq_f32(
    float32x4_t a, const int lane1, float32x4_t b, const int lane2);  // INS Vd.S[lane1],Vn.S[lane2]
float64x1_t vcopy_laneq_f64(
    float64x1_t a, const int lane1, float64x2_t b, const int lane2);  // DUP Dd,Vn.D[lane2]
float64x2_t vcopyq_laneq_f64(
    float64x2_t a, const int lane1, float64x2_t b, const int lane2);  // INS Vd.D[lane1],Vn.D[lane2]
poly8x8_t vcopy_laneq_p8(
    poly8x8_t a, const int lane1, poly8x16_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
poly8x16_t vcopyq_laneq_p8(
    poly8x16_t a, const int lane1, poly8x16_t b, const int lane2);  // INS Vd.B[lane1],Vn.B[lane2]
poly16x4_t vcopy_laneq_p16(
    poly16x4_t a, const int lane1, poly16x8_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
poly16x8_t vcopyq_laneq_p16(
    poly16x8_t a, const int lane1, poly16x8_t b, const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
int8x8_t vrbit_s8(int8x8_t a);                                      // RBIT Vd.8B,Vn.8B
int8x16_t vrbitq_s8(int8x16_t a);                                   // RBIT Vd.16B,Vn.16B
uint8x8_t vrbit_u8(uint8x8_t a);                                    // RBIT Vd.8B,Vn.8B
uint8x16_t vrbitq_u8(uint8x16_t a);                                 // RBIT Vd.16B,Vn.16B
poly8x8_t vrbit_p8(poly8x8_t a);                                    // RBIT Vd.8B,Vn.8B
poly8x16_t vrbitq_p8(poly8x16_t a);                                 // RBIT Vd.16B,Vn.16B
int8x8_t vcreate_s8(uint64_t a);                                    // INS Vd.D[0],Xn
int16x4_t vcreate_s16(uint64_t a);                                  // INS Vd.D[0],Xn
int32x2_t vcreate_s32(uint64_t a);                                  // INS Vd.D[0],Xn
int64x1_t vcreate_s64(uint64_t a);                                  // INS Vd.D[0],Xn
uint8x8_t vcreate_u8(uint64_t a);                                   // INS Vd.D[0],Xn
uint16x4_t vcreate_u16(uint64_t a);                                 // INS Vd.D[0],Xn
uint32x2_t vcreate_u32(uint64_t a);                                 // INS Vd.D[0],Xn
uint64x1_t vcreate_u64(uint64_t a);                                 // INS Vd.D[0],Xn
poly64x1_t vcreate_p64(uint64_t a);                                 // INS Vd.D[0],Xn
float16x4_t vcreate_f16(uint64_t a);                                // INS Vd.D[0],Xn
float32x2_t vcreate_f32(uint64_t a);                                // INS Vd.D[0],Xn
poly8x8_t vcreate_p8(uint64_t a);                                   // INS Vd.D[0],Xn
poly16x4_t vcreate_p16(uint64_t a);                                 // INS Vd.D[0],Xn
float64x1_t vcreate_f64(uint64_t a);                                // INS Vd.D[0],Xn
int8x8_t vdup_n_s8(int8_t value);                                   // DUP Vd.8B,rn
int8x16_t vdupq_n_s8(int8_t value);                                 // DUP Vd.16B,rn
int16x4_t vdup_n_s16(int16_t value);                                // DUP Vd.4H,rn
int16x8_t vdupq_n_s16(int16_t value);                               // DUP Vd.8H,rn
int32x2_t vdup_n_s32(int32_t value);                                // DUP Vd.2S,rn
int32x4_t vdupq_n_s32(int32_t value);                               // DUP Vd.4S,rn
int64x1_t vdup_n_s64(int64_t value);                                // INS Dd.D[0],xn
int64x2_t vdupq_n_s64(int64_t value);                               // DUP Vd.2D,rn
uint8x8_t vdup_n_u8(uint8_t value);                                 // DUP Vd.8B,rn
uint8x16_t vdupq_n_u8(uint8_t value);                               // DUP Vd.16B,rn
uint16x4_t vdup_n_u16(uint16_t value);                              // DUP Vd.4H,rn
uint16x8_t vdupq_n_u16(uint16_t value);                             // DUP Vd.8H,rn
uint32x2_t vdup_n_u32(uint32_t value);                              // DUP Vd.2S,rn
uint32x4_t vdupq_n_u32(uint32_t value);                             // DUP Vd.4S,rn
uint64x1_t vdup_n_u64(uint64_t value);                              // INS Dd.D[0],xn
uint64x2_t vdupq_n_u64(uint64_t value);                             // DUP Vd.2D,rn
poly64x1_t vdup_n_p64(poly64_t value);                              // INS Dd.D[0],xn
poly64x2_t vdupq_n_p64(poly64_t value);                             // DUP Vd.2D,rn
float32x2_t vdup_n_f32(float32_t value);                            // DUP Vd.2S,rn
float32x4_t vdupq_n_f32(float32_t value);                           // DUP Vd.4S,rn
poly8x8_t vdup_n_p8(poly8_t value);                                 // DUP Vd.8B,rn
poly8x16_t vdupq_n_p8(poly8_t value);                               // DUP Vd.16B,rn
poly16x4_t vdup_n_p16(poly16_t value);                              // DUP Vd.4H,rn
poly16x8_t vdupq_n_p16(poly16_t value);                             // DUP Vd.8H,rn
float64x1_t vdup_n_f64(float64_t value);                            // INS Dd.D[0],xn
float64x2_t vdupq_n_f64(float64_t value);                           // DUP Vd.2D,rn
int8x8_t vmov_n_s8(int8_t value);                                   // DUP Vd.8B,rn
int8x16_t vmovq_n_s8(int8_t value);                                 // DUP Vd.16B,rn
int16x4_t vmov_n_s16(int16_t value);                                // DUP Vd.4H,rn
int16x8_t vmovq_n_s16(int16_t value);                               // DUP Vd.8H,rn
int32x2_t vmov_n_s32(int32_t value);                                // DUP Vd.2S,rn
int32x4_t vmovq_n_s32(int32_t value);                               // DUP Vd.4S,rn
int64x1_t vmov_n_s64(int64_t value);                                // DUP Vd.1D,rn
int64x2_t vmovq_n_s64(int64_t value);                               // DUP Vd.2D,rn
uint8x8_t vmov_n_u8(uint8_t value);                                 // DUP Vd.8B,rn
uint8x16_t vmovq_n_u8(uint8_t value);                               // DUP Vd.16B,rn
uint16x4_t vmov_n_u16(uint16_t value);                              // DUP Vd.4H,rn
uint16x8_t vmovq_n_u16(uint16_t value);                             // DUP Vd.8H,rn
uint32x2_t vmov_n_u32(uint32_t value);                              // DUP Vd.2S,rn
uint32x4_t vmovq_n_u32(uint32_t value);                             // DUP Vd.4S,rn
uint64x1_t vmov_n_u64(uint64_t value);                              // DUP Vd.1D,rn
uint64x2_t vmovq_n_u64(uint64_t value);                             // DUP Vd.2D,rn
float32x2_t vmov_n_f32(float32_t value);                            // DUP Vd.2S,rn
float32x4_t vmovq_n_f32(float32_t value);                           // DUP Vd.4S,rn
poly8x8_t vmov_n_p8(poly8_t value);                                 // DUP Vd.8B,rn
poly8x16_t vmovq_n_p8(poly8_t value);                               // DUP Vd.16B,rn
poly16x4_t vmov_n_p16(poly16_t value);                              // DUP Vd.4H,rn
poly16x8_t vmovq_n_p16(poly16_t value);                             // DUP Vd.8H,rn
float64x1_t vmov_n_f64(float64_t value);                            // DUP Vd.1D,rn
float64x2_t vmovq_n_f64(float64_t value);                           // DUP Vd.2D,rn
int8x8_t vdup_lane_s8(int8x8_t vec, const int lane);                // DUP Vd.8B,Vn.B[lane]
int8x16_t vdupq_lane_s8(int8x8_t vec, const int lane);              // DUP Vd.16B,Vn.B[lane]
int16x4_t vdup_lane_s16(int16x4_t vec, const int lane);             // DUP Vd.4H,Vn.H[lane]
int16x8_t vdupq_lane_s16(int16x4_t vec, const int lane);            // DUP Vd.8H,Vn.H[lane]
int32x2_t vdup_lane_s32(int32x2_t vec, const int lane);             // DUP Vd.2S,Vn.S[lane]
int32x4_t vdupq_lane_s32(int32x2_t vec, const int lane);            // DUP Vd.4S,Vn.S[lane]
int64x1_t vdup_lane_s64(int64x1_t vec, const int lane);             // DUP Dd,Vn.D[lane]
int64x2_t vdupq_lane_s64(int64x1_t vec, const int lane);            // DUP Vd.2D,Vn.D[lane]
uint8x8_t vdup_lane_u8(uint8x8_t vec, const int lane);              // DUP Vd.8B,Vn.B[lane]
uint8x16_t vdupq_lane_u8(uint8x8_t vec, const int lane);            // DUP Vd.16B,Vn.B[lane]
uint16x4_t vdup_lane_u16(uint16x4_t vec, const int lane);           // DUP Vd.4H,Vn.H[lane]
uint16x8_t vdupq_lane_u16(uint16x4_t vec, const int lane);          // DUP Vd.8H,Vn.H[lane]
uint32x2_t vdup_lane_u32(uint32x2_t vec, const int lane);           // DUP Vd.2S,Vn.S[lane]
uint32x4_t vdupq_lane_u32(uint32x2_t vec, const int lane);          // DUP Vd.4S,Vn.S[lane]
uint64x1_t vdup_lane_u64(uint64x1_t vec, const int lane);           // DUP Dd,Vn.D[lane]
uint64x2_t vdupq_lane_u64(uint64x1_t vec, const int lane);          // DUP Vd.2D,Vn.D[lane]
poly64x1_t vdup_lane_p64(poly64x1_t vec, const int lane);           // DUP Dd,Vn.D[lane]
poly64x2_t vdupq_lane_p64(poly64x1_t vec, const int lane);          // DUP Vd.2D,Vn.D[lane]
float32x2_t vdup_lane_f32(float32x2_t vec, const int lane);         // DUP Vd.2S,Vn.S[lane]
float32x4_t vdupq_lane_f32(float32x2_t vec, const int lane);        // DUP Vd.4S,Vn.S[lane]
poly8x8_t vdup_lane_p8(poly8x8_t vec, const int lane);              // DUP Vd.8B,Vn.B[lane]
poly8x16_t vdupq_lane_p8(poly8x8_t vec, const int lane);            // DUP Vd.16B,Vn.B[lane]
poly16x4_t vdup_lane_p16(poly16x4_t vec, const int lane);           // DUP Vd.4H,Vn.H[lane]
poly16x8_t vdupq_lane_p16(poly16x4_t vec, const int lane);          // DUP Vd.8H,Vn.H[lane]
float64x1_t vdup_lane_f64(float64x1_t vec, const int lane);         // DUP Dd,Vn.D[lane]
float64x2_t vdupq_lane_f64(float64x1_t vec, const int lane);        // DUP Vd.2D,Vn.D[lane]
int8x8_t vdup_laneq_s8(int8x16_t vec, const int lane);              // DUP Vd.8B,Vn.B[lane]
int8x16_t vdupq_laneq_s8(int8x16_t vec, const int lane);            // DUP Vd.16B,Vn.B[lane]
int16x4_t vdup_laneq_s16(int16x8_t vec, const int lane);            // DUP Vd.4H,Vn.H[lane]
int16x8_t vdupq_laneq_s16(int16x8_t vec, const int lane);           // DUP Vd.8H,Vn.H[lane]
int32x2_t vdup_laneq_s32(int32x4_t vec, const int lane);            // DUP Vd.2S,Vn.S[lane]
int32x4_t vdupq_laneq_s32(int32x4_t vec, const int lane);           // DUP Vd.4S,Vn.S[lane]
int64x1_t vdup_laneq_s64(int64x2_t vec, const int lane);            // DUP Dd,Vn.D[lane]
int64x2_t vdupq_laneq_s64(int64x2_t vec, const int lane);           // DUP Vd.2D,Vn.D[lane]
uint8x8_t vdup_laneq_u8(uint8x16_t vec, const int lane);            // DUP Vd.8B,Vn.B[lane]
uint8x16_t vdupq_laneq_u8(uint8x16_t vec, const int lane);          // DUP Vd.16B,Vn.B[lane]
uint16x4_t vdup_laneq_u16(uint16x8_t vec, const int lane);          // DUP Vd.4H,Vn.H[lane]
uint16x8_t vdupq_laneq_u16(uint16x8_t vec, const int lane);         // DUP Vd.8H,Vn.H[lane]
uint32x2_t vdup_laneq_u32(uint32x4_t vec, const int lane);          // DUP Vd.2S,Vn.S[lane]
uint32x4_t vdupq_laneq_u32(uint32x4_t vec, const int lane);         // DUP Vd.4S,Vn.S[lane]
uint64x1_t vdup_laneq_u64(uint64x2_t vec, const int lane);          // DUP Dd,Vn.D[lane]
uint64x2_t vdupq_laneq_u64(uint64x2_t vec, const int lane);         // DUP Vd.2D,Vn.D[lane]
poly64x1_t vdup_laneq_p64(poly64x2_t vec, const int lane);          // DUP Dd,Vn.D[lane]
poly64x2_t vdupq_laneq_p64(poly64x2_t vec, const int lane);         // DUP Vd.2D,Vn.D[lane]
float32x2_t vdup_laneq_f32(float32x4_t vec, const int lane);        // DUP Vd.2S,Vn.S[lane]
float32x4_t vdupq_laneq_f32(float32x4_t vec, const int lane);       // DUP Vd.4S,Vn.S[lane]
poly8x8_t vdup_laneq_p8(poly8x16_t vec, const int lane);            // DUP Vd.8B,Vn.B[lane]
poly8x16_t vdupq_laneq_p8(poly8x16_t vec, const int lane);          // DUP Vd.16B,Vn.B[lane]
poly16x4_t vdup_laneq_p16(poly16x8_t vec, const int lane);          // DUP Vd.4H,Vn.H[lane]
poly16x8_t vdupq_laneq_p16(poly16x8_t vec, const int lane);         // DUP Vd.8H,Vn.H[lane]
float64x1_t vdup_laneq_f64(float64x2_t vec, const int lane);        // DUP Dd,Vn.D[lane]
float64x2_t vdupq_laneq_f64(float64x2_t vec, const int lane);       // DUP Vd.2D,Vn.D[lane]
int8x16_t vcombine_s8(int8x8_t low, int8x8_t high);        // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
int16x8_t vcombine_s16(int16x4_t low, int16x4_t high);     // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
int32x4_t vcombine_s32(int32x2_t low, int32x2_t high);     // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
int64x2_t vcombine_s64(int64x1_t low, int64x1_t high);     // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
uint8x16_t vcombine_u8(uint8x8_t low, uint8x8_t high);     // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
uint16x8_t vcombine_u16(uint16x4_t low, uint16x4_t high);  // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
uint32x4_t vcombine_u32(uint32x2_t low, uint32x2_t high);  // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
uint64x2_t vcombine_u64(uint64x1_t low, uint64x1_t high);  // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
poly64x2_t vcombine_p64(poly64x1_t low, poly64x1_t high);  // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
float16x8_t vcombine_f16(
    float16x4_t low, float16x4_t high);  // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
float32x4_t vcombine_f32(
    float32x2_t low, float32x2_t high);                    // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
poly8x16_t vcombine_p8(poly8x8_t low, poly8x8_t high);     // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
poly16x8_t vcombine_p16(poly16x4_t low, poly16x4_t high);  // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
float64x2_t vcombine_f64(
    float64x1_t low, float64x1_t high);                   // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
int8x8_t vget_high_s8(int8x16_t a);                       // DUP Vd.1D,Vn.D[1]
int16x4_t vget_high_s16(int16x8_t a);                     // DUP Vd.1D,Vn.D[1]
int32x2_t vget_high_s32(int32x4_t a);                     // DUP Vd.1D,Vn.D[1]
int64x1_t vget_high_s64(int64x2_t a);                     // DUP Vd.1D,Vn.D[1]
uint8x8_t vget_high_u8(uint8x16_t a);                     // DUP Vd.1D,Vn.D[1]
uint16x4_t vget_high_u16(uint16x8_t a);                   // DUP Vd.1D,Vn.D[1]
uint32x2_t vget_high_u32(uint32x4_t a);                   // DUP Vd.1D,Vn.D[1]
uint64x1_t vget_high_u64(uint64x2_t a);                   // DUP Vd.1D,Vn.D[1]
poly64x1_t vget_high_p64(poly64x2_t a);                   // DUP Vd.1D,Vn.D[1]
float16x4_t vget_high_f16(float16x8_t a);                 // DUP Vd.1D,Vn.D[1]
float32x2_t vget_high_f32(float32x4_t a);                 // DUP Vd.1D,Vn.D[1]
poly8x8_t vget_high_p8(poly8x16_t a);                     // DUP Vd.1D,Vn.D[1]
poly16x4_t vget_high_p16(poly16x8_t a);                   // DUP Vd.1D,Vn.D[1]
float64x1_t vget_high_f64(float64x2_t a);                 // DUP Vd.1D,Vn.D[1]
int8x8_t vget_low_s8(int8x16_t a);                        // DUP Vd.1D,Vn.D[0]
int16x4_t vget_low_s16(int16x8_t a);                      // DUP Vd.1D,Vn.D[0]
int32x2_t vget_low_s32(int32x4_t a);                      // DUP Vd.1D,Vn.D[0]
int64x1_t vget_low_s64(int64x2_t a);                      // DUP Vd.1D,Vn.D[0]
uint8x8_t vget_low_u8(uint8x16_t a);                      // DUP Vd.1D,Vn.D[0]
uint16x4_t vget_low_u16(uint16x8_t a);                    // DUP Vd.1D,Vn.D[0]
uint32x2_t vget_low_u32(uint32x4_t a);                    // DUP Vd.1D,Vn.D[0]
uint64x1_t vget_low_u64(uint64x2_t a);                    // DUP Vd.1D,Vn.D[0]
poly64x1_t vget_low_p64(poly64x2_t a);                    // DUP Vd.1D,Vn.D[0]
float16x4_t vget_low_f16(float16x8_t a);                  // DUP Vd.1D,Vn.D[0]
float32x2_t vget_low_f32(float32x4_t a);                  // DUP Vd.1D,Vn.D[0]
poly8x8_t vget_low_p8(poly8x16_t a);                      // DUP Vd.1D,Vn.D[0]
poly16x4_t vget_low_p16(poly16x8_t a);                    // DUP Vd.1D,Vn.D[0]
float64x1_t vget_low_f64(float64x2_t a);                  // DUP Vd.1D,Vn.D[0]
int8_t vdupb_lane_s8(int8x8_t vec, const int lane);       // DUP Bd,Vn.B[lane]
int16_t vduph_lane_s16(int16x4_t vec, const int lane);    // DUP Hd,Vn.H[lane]
int32_t vdups_lane_s32(int32x2_t vec, const int lane);    // DUP Sd,Vn.S[lane]
int64_t vdupd_lane_s64(int64x1_t vec, const int lane);    // DUP Dd,Vn.D[lane]
uint8_t vdupb_lane_u8(uint8x8_t vec, const int lane);     // DUP Bd,Vn.B[lane]
uint16_t vduph_lane_u16(uint16x4_t vec, const int lane);  // DUP Hd,Vn.H[lane]
uint32_t vdups_lane_u32(uint32x2_t vec, const int lane);  // DUP Sd,Vn.S[lane]
uint64_t vdupd_lane_u64(uint64x1_t vec, const int lane);  // DUP Dd,Vn.D[lane]
float32_t vdups_lane_f32(float32x2_t vec, const int lane);                  // DUP Sd,Vn.S[lane]
float64_t vdupd_lane_f64(float64x1_t vec, const int lane);                  // DUP Dd,Vn.D[lane]
poly8_t vdupb_lane_p8(poly8x8_t vec, const int lane);                       // DUP Bd,Vn.B[lane]
poly16_t vduph_lane_p16(poly16x4_t vec, const int lane);                    // DUP Hd,Vn.H[lane]
int8_t vdupb_laneq_s8(int8x16_t vec, const int lane);                       // DUP Bd,Vn.B[lane]
int16_t vduph_laneq_s16(int16x8_t vec, const int lane);                     // DUP Hd,Vn.H[lane]
int32_t vdups_laneq_s32(int32x4_t vec, const int lane);                     // DUP Sd,Vn.S[lane]
int64_t vdupd_laneq_s64(int64x2_t vec, const int lane);                     // DUP Dd,Vn.D[lane]
uint8_t vdupb_laneq_u8(uint8x16_t vec, const int lane);                     // DUP Bd,Vn.B[lane]
uint16_t vduph_laneq_u16(uint16x8_t vec, const int lane);                   // DUP Hd,Vn.H[lane]
uint32_t vdups_laneq_u32(uint32x4_t vec, const int lane);                   // DUP Sd,Vn.S[lane]
uint64_t vdupd_laneq_u64(uint64x2_t vec, const int lane);                   // DUP Dd,Vn.D[lane]
float32_t vdups_laneq_f32(float32x4_t vec, const int lane);                 // DUP Sd,Vn.S[lane]
float64_t vdupd_laneq_f64(float64x2_t vec, const int lane);                 // DUP Dd,Vn.D[lane]
poly8_t vdupb_laneq_p8(poly8x16_t vec, const int lane);                     // DUP Bd,Vn.B[lane]
poly16_t vduph_laneq_p16(poly16x8_t vec, const int lane);                   // DUP Hd,Vn.H[lane]
int8x8_t vld1_s8(int8_t const* ptr);                                        // LD1 {Vt.8B},[Xn]
int8x16_t vld1q_s8(int8_t const* ptr);                                      // LD1 {Vt.16B},[Xn]
int16x4_t vld1_s16(int16_t const* ptr);                                     // LD1 {Vt.4H},[Xn]
int16x8_t vld1q_s16(int16_t const* ptr);                                    // LD1 {Vt.8H},[Xn]
int32x2_t vld1_s32(int32_t const* ptr);                                     // LD1 {Vt.2S},[Xn]
int32x4_t vld1q_s32(int32_t const* ptr);                                    // LD1 {Vt.4S},[Xn]
int64x1_t vld1_s64(int64_t const* ptr);                                     // LD1 {Vt.1D},[Xn]
int64x2_t vld1q_s64(int64_t const* ptr);                                    // LD1 {Vt.2D},[Xn]
uint8x8_t vld1_u8(uint8_t const* ptr);                                      // LD1 {Vt.8B},[Xn]
uint8x16_t vld1q_u8(uint8_t const* ptr);                                    // LD1 {Vt.16B},[Xn]
uint16x4_t vld1_u16(uint16_t const* ptr);                                   // LD1 {Vt.4H},[Xn]
uint16x8_t vld1q_u16(uint16_t const* ptr);                                  // LD1 {Vt.8H},[Xn]
uint32x2_t vld1_u32(uint32_t const* ptr);                                   // LD1 {Vt.2S},[Xn]
uint32x4_t vld1q_u32(uint32_t const* ptr);                                  // LD1 {Vt.4S},[Xn]
uint64x1_t vld1_u64(uint64_t const* ptr);                                   // LD1 {Vt.1D},[Xn]
uint64x2_t vld1q_u64(uint64_t const* ptr);                                  // LD1 {Vt.2D},[Xn]
poly64x1_t vld1_p64(poly64_t const* ptr);                                   // LD1 {Vt.1D},[Xn]
poly64x2_t vld1q_p64(poly64_t const* ptr);                                  // LD1 {Vt.2D},[Xn]
float16x4_t vld1_f16(float16_t const* ptr);                                 // LD1 {Vt.4H},[Xn]
float16x8_t vld1q_f16(float16_t const* ptr);                                // LD1 {Vt.8H},[Xn]
float32x2_t vld1_f32(float32_t const* ptr);                                 // LD1 {Vt.2S},[Xn]
float32x4_t vld1q_f32(float32_t const* ptr);                                // LD1 {Vt.4S},[Xn]
poly8x8_t vld1_p8(poly8_t const* ptr);                                      // LD1 {Vt.8B},[Xn]
poly8x16_t vld1q_p8(poly8_t const* ptr);                                    // LD1 {Vt.16B},[Xn]
poly16x4_t vld1_p16(poly16_t const* ptr);                                   // LD1 {Vt.4H},[Xn]
poly16x8_t vld1q_p16(poly16_t const* ptr);                                  // LD1 {Vt.8H},[Xn]
float64x1_t vld1_f64(float64_t const* ptr);                                 // LD1 {Vt.1D},[Xn]
float64x2_t vld1q_f64(float64_t const* ptr);                                // LD1 {Vt.2D},[Xn]
int8x8_t vld1_lane_s8(int8_t const* ptr, int8x8_t src, const int lane);     // LD1 {Vt.b}[lane],[Xn]
int8x16_t vld1q_lane_s8(int8_t const* ptr, int8x16_t src, const int lane);  // LD1 {Vt.b}[lane],[Xn]
int16x4_t vld1_lane_s16(
    int16_t const* ptr, int16x4_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
int16x8_t vld1q_lane_s16(
    int16_t const* ptr, int16x8_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
int32x2_t vld1_lane_s32(
    int32_t const* ptr, int32x2_t src, const int lane);  // LD1 {Vt.S}[lane],[Xn]
int32x4_t vld1q_lane_s32(
    int32_t const* ptr, int32x4_t src, const int lane);  // LD1 {Vt.S}[lane],[Xn]
int64x1_t vld1_lane_s64(
    int64_t const* ptr, int64x1_t src, const int lane);  // LD1 {Vt.D}[lane],[Xn]
int64x2_t vld1q_lane_s64(
    int64_t const* ptr, int64x2_t src, const int lane);                     // LD1 {Vt.D}[lane],[Xn]
uint8x8_t vld1_lane_u8(uint8_t const* ptr, uint8x8_t src, const int lane);  // LD1 {Vt.B}[lane],[Xn]
uint8x16_t vld1q_lane_u8(
    uint8_t const* ptr, uint8x16_t src, const int lane);  // LD1 {Vt.B}[lane],[Xn]
uint16x4_t vld1_lane_u16(
    uint16_t const* ptr, uint16x4_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
uint16x8_t vld1q_lane_u16(
    uint16_t const* ptr, uint16x8_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
uint32x2_t vld1_lane_u32(
    uint32_t const* ptr, uint32x2_t src, const int lane);  // LD1 {Vt.S}[lane],[Xn]
uint32x4_t vld1q_lane_u32(
    uint32_t const* ptr, uint32x4_t src, const int lane);  // LD1 {Vt.S}[lane],[Xn]
uint64x1_t vld1_lane_u64(
    uint64_t const* ptr, uint64x1_t src, const int lane);  // LD1 {Vt.D}[lane],[Xn]
uint64x2_t vld1q_lane_u64(
    uint64_t const* ptr, uint64x2_t src, const int lane);  // LD1 {Vt.D}[lane],[Xn]
poly64x1_t vld1_lane_p64(
    poly64_t const* ptr, poly64x1_t src, const int lane);  // LD1 {Vt.D}[lane],[Xn]
poly64x2_t vld1q_lane_p64(
    poly64_t const* ptr, poly64x2_t src, const int lane);  // LD1 {Vt.D}[lane],[Xn]
float16x4_t vld1_lane_f16(
    float16_t const* ptr, float16x4_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
float16x8_t vld1q_lane_f16(
    float16_t const* ptr, float16x8_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
float32x2_t vld1_lane_f32(
    float32_t const* ptr, float32x2_t src, const int lane);  // LD1 {Vt.S}[lane],[Xn]
float32x4_t vld1q_lane_f32(
    float32_t const* ptr, float32x4_t src, const int lane);                 // LD1 {Vt.S}[lane],[Xn]
poly8x8_t vld1_lane_p8(poly8_t const* ptr, poly8x8_t src, const int lane);  // LD1 {Vt.B}[lane],[Xn]
poly8x16_t vld1q_lane_p8(
    poly8_t const* ptr, poly8x16_t src, const int lane);  // LD1 {Vt.B}[lane],[Xn]
poly16x4_t vld1_lane_p16(
    poly16_t const* ptr, poly16x4_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
poly16x8_t vld1q_lane_p16(
    poly16_t const* ptr, poly16x8_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
float64x1_t vld1_lane_f64(
    float64_t const* ptr, float64x1_t src, const int lane);  // LD1 {Vt.D}[lane],[Xn]
float64x2_t vld1q_lane_f64(
    float64_t const* ptr, float64x2_t src, const int lane);            // LD1 {Vt.D}[lane],[Xn]
int8x8_t vld1_dup_s8(int8_t const* ptr);                               // LD1R {Vt.8B},[Xn]
int8x16_t vld1q_dup_s8(int8_t const* ptr);                             // LD1R {Vt.16B},[Xn]
int16x4_t vld1_dup_s16(int16_t const* ptr);                            // LD1R {Vt.4H},[Xn]
int16x8_t vld1q_dup_s16(int16_t const* ptr);                           // LD1R {Vt.8H},[Xn]
int32x2_t vld1_dup_s32(int32_t const* ptr);                            // LD1R {Vt.2S},[Xn]
int32x4_t vld1q_dup_s32(int32_t const* ptr);                           // LD1R {Vt.4S},[Xn]
int64x1_t vld1_dup_s64(int64_t const* ptr);                            // LD1 {Vt.1D},[Xn]
int64x2_t vld1q_dup_s64(int64_t const* ptr);                           // LD1R {Vt.2D},[Xn]
uint8x8_t vld1_dup_u8(uint8_t const* ptr);                             // LD1R {Vt.8B},[Xn]
uint8x16_t vld1q_dup_u8(uint8_t const* ptr);                           // LD1R {Vt.16B},[Xn]
uint16x4_t vld1_dup_u16(uint16_t const* ptr);                          // LD1R {Vt.4H},[Xn]
uint16x8_t vld1q_dup_u16(uint16_t const* ptr);                         // LD1R {Vt.8H},[Xn]
uint32x2_t vld1_dup_u32(uint32_t const* ptr);                          // LD1R {Vt.2S},[Xn]
uint32x4_t vld1q_dup_u32(uint32_t const* ptr);                         // LD1R {Vt.4S},[Xn]
uint64x1_t vld1_dup_u64(uint64_t const* ptr);                          // LD1 {Vt.1D},[Xn]
uint64x2_t vld1q_dup_u64(uint64_t const* ptr);                         // LD1R {Vt.2D},[Xn]
poly64x1_t vld1_dup_p64(poly64_t const* ptr);                          // LD1 {Vt.1D},[Xn]
poly64x2_t vld1q_dup_p64(poly64_t const* ptr);                         // LD1R {Vt.2D},[Xn]
float16x4_t vld1_dup_f16(float16_t const* ptr);                        // LD1R {Vt.4H},[Xn]
float16x8_t vld1q_dup_f16(float16_t const* ptr);                       // LD1R {Vt.8H},[Xn]
float32x2_t vld1_dup_f32(float32_t const* ptr);                        // LD1R {Vt.2S},[Xn]
float32x4_t vld1q_dup_f32(float32_t const* ptr);                       // LD1R {Vt.4S},[Xn]
poly8x8_t vld1_dup_p8(poly8_t const* ptr);                             // LD1R {Vt.8B},[Xn]
poly8x16_t vld1q_dup_p8(poly8_t const* ptr);                           // LD1R {Vt.16B},[Xn]
poly16x4_t vld1_dup_p16(poly16_t const* ptr);                          // LD1R {Vt.4H},[Xn]
poly16x8_t vld1q_dup_p16(poly16_t const* ptr);                         // LD1R {Vt.8H},[Xn]
float64x1_t vld1_dup_f64(float64_t const* ptr);                        // LD1 {Vt.1D},[Xn]
float64x2_t vld1q_dup_f64(float64_t const* ptr);                       // LD1R {Vt.2D},[Xn]
void vst1_s8(int8_t* ptr, int8x8_t val);                               // ST1 {Vt.8B},[Xn]
void vst1q_s8(int8_t* ptr, int8x16_t val);                             // ST1 {Vt.16B},[Xn]
void vst1_s16(int16_t* ptr, int16x4_t val);                            // ST1 {Vt.4H},[Xn]
void vst1q_s16(int16_t* ptr, int16x8_t val);                           // ST1 {Vt.8H},[Xn]
void vst1_s32(int32_t* ptr, int32x2_t val);                            // ST1 {Vt.2S},[Xn]
void vst1q_s32(int32_t* ptr, int32x4_t val);                           // ST1 {Vt.4S},[Xn]
void vst1_s64(int64_t* ptr, int64x1_t val);                            // ST1 {Vt.1D},[Xn]
void vst1q_s64(int64_t* ptr, int64x2_t val);                           // ST1 {Vt.2D},[Xn]
void vst1_u8(uint8_t* ptr, uint8x8_t val);                             // ST1 {Vt.8B},[Xn]
void vst1q_u8(uint8_t* ptr, uint8x16_t val);                           // ST1 {Vt.16B},[Xn]
void vst1_u16(uint16_t* ptr, uint16x4_t val);                          // ST1 {Vt.4H},[Xn]
void vst1q_u16(uint16_t* ptr, uint16x8_t val);                         // ST1 {Vt.8H},[Xn]
void vst1_u32(uint32_t* ptr, uint32x2_t val);                          // ST1 {Vt.2S},[Xn]
void vst1q_u32(uint32_t* ptr, uint32x4_t val);                         // ST1 {Vt.4S},[Xn]
void vst1_u64(uint64_t* ptr, uint64x1_t val);                          // ST1 {Vt.1D},[Xn]
void vst1q_u64(uint64_t* ptr, uint64x2_t val);                         // ST1 {Vt.2D},[Xn]
void vst1_p64(poly64_t* ptr, poly64x1_t val);                          // ST1 {Vt.1D},[Xn]
void vst1q_p64(poly64_t* ptr, poly64x2_t val);                         // ST1 {Vt.2D},[Xn]
void vst1_f16(float16_t* ptr, float16x4_t val);                        // ST1 {Vt.4H},[Xn]
void vst1q_f16(float16_t* ptr, float16x8_t val);                       // ST1 {Vt.8H},[Xn]
void vst1_f32(float32_t* ptr, float32x2_t val);                        // ST1 {Vt.2S},[Xn]
void vst1q_f32(float32_t* ptr, float32x4_t val);                       // ST1 {Vt.4S},[Xn]
void vst1_p8(poly8_t* ptr, poly8x8_t val);                             // ST1 {Vt.8B},[Xn]
void vst1q_p8(poly8_t* ptr, poly8x16_t val);                           // ST1 {Vt.16B},[Xn]
void vst1_p16(poly16_t* ptr, poly16x4_t val);                          // ST1 {Vt.4H},[Xn]
void vst1q_p16(poly16_t* ptr, poly16x8_t val);                         // ST1 {Vt.8H},[Xn]
void vst1_f64(float64_t* ptr, float64x1_t val);                        // ST1 {Vt.1D},[Xn]
void vst1q_f64(float64_t* ptr, float64x2_t val);                       // ST1 {Vt.2D},[Xn]
void vst1_lane_s8(int8_t* ptr, int8x8_t val, const int lane);          // ST1 {Vt.b}[lane],[Xn]
void vst1q_lane_s8(int8_t* ptr, int8x16_t val, const int lane);        // ST1 {Vt.b}[lane],[Xn]
void vst1_lane_s16(int16_t* ptr, int16x4_t val, const int lane);       // ST1 {Vt.h}[lane],[Xn]
void vst1q_lane_s16(int16_t* ptr, int16x8_t val, const int lane);      // ST1 {Vt.h}[lane],[Xn]
void vst1_lane_s32(int32_t* ptr, int32x2_t val, const int lane);       // ST1 {Vt.s}[lane],[Xn]
void vst1q_lane_s32(int32_t* ptr, int32x4_t val, const int lane);      // ST1 {Vt.s}[lane],[Xn]
void vst1_lane_s64(int64_t* ptr, int64x1_t val, const int lane);       // ST1 {Vt.d}[lane],[Xn]
void vst1q_lane_s64(int64_t* ptr, int64x2_t val, const int lane);      // ST1 {Vt.d}[lane],[Xn]
void vst1_lane_u8(uint8_t* ptr, uint8x8_t val, const int lane);        // ST1 {Vt.b}[lane],[Xn]
void vst1q_lane_u8(uint8_t* ptr, uint8x16_t val, const int lane);      // ST1 {Vt.b}[lane],[Xn]
void vst1_lane_u16(uint16_t* ptr, uint16x4_t val, const int lane);     // ST1 {Vt.h}[lane],[Xn]
void vst1q_lane_u16(uint16_t* ptr, uint16x8_t val, const int lane);    // ST1 {Vt.h}[lane],[Xn]
void vst1_lane_u32(uint32_t* ptr, uint32x2_t val, const int lane);     // ST1 {Vt.s}[lane],[Xn]
void vst1q_lane_u32(uint32_t* ptr, uint32x4_t val, const int lane);    // ST1 {Vt.s}[lane],[Xn]
void vst1_lane_u64(uint64_t* ptr, uint64x1_t val, const int lane);     // ST1 {Vt.d}[lane],[Xn]
void vst1q_lane_u64(uint64_t* ptr, uint64x2_t val, const int lane);    // ST1 {Vt.d}[lane],[Xn]
void vst1_lane_p64(poly64_t* ptr, poly64x1_t val, const int lane);     // ST1 {Vt.d}[lane],[Xn]
void vst1q_lane_p64(poly64_t* ptr, poly64x2_t val, const int lane);    // ST1 {Vt.d}[lane],[Xn]
void vst1_lane_f16(float16_t* ptr, float16x4_t val, const int lane);   // ST1 {Vt.h}[lane],[Xn]
void vst1q_lane_f16(float16_t* ptr, float16x8_t val, const int lane);  // ST1 {Vt.h}[lane],[Xn]
void vst1_lane_f32(float32_t* ptr, float32x2_t val, const int lane);   // ST1 {Vt.s}[lane],[Xn]
void vst1q_lane_f32(float32_t* ptr, float32x4_t val, const int lane);  // ST1 {Vt.s}[lane],[Xn]
void vst1_lane_p8(poly8_t* ptr, poly8x8_t val, const int lane);        // ST1 {Vt.b}[lane],[Xn]
void vst1q_lane_p8(poly8_t* ptr, poly8x16_t val, const int lane);      // ST1 {Vt.b}[lane],[Xn]
void vst1_lane_p16(poly16_t* ptr, poly16x4_t val, const int lane);     // ST1 {Vt.h}[lane],[Xn]
void vst1q_lane_p16(poly16_t* ptr, poly16x8_t val, const int lane);    // ST1 {Vt.h}[lane],[Xn]
void vst1_lane_f64(float64_t* ptr, float64x1_t val, const int lane);   // ST1 {Vt.d}[lane],[Xn]
void vst1q_lane_f64(float64_t* ptr, float64x2_t val, const int lane);  // ST1 {Vt.d}[lane],[Xn]
int8x8x2_t vld2_s8(int8_t const* ptr);                                 // LD2 {Vt.8B - Vt2.8B},[Xn]
int8x16x2_t vld2q_s8(int8_t const* ptr);            // LD2 {Vt.16B - Vt2.16B},[Xn]
int16x4x2_t vld2_s16(int16_t const* ptr);           // LD2 {Vt.4H - Vt2.4H},[Xn]
int16x8x2_t vld2q_s16(int16_t const* ptr);          // LD2 {Vt.8H - Vt2.8H},[Xn]
int32x2x2_t vld2_s32(int32_t const* ptr);           // LD2 {Vt.2S - Vt2.2S},[Xn]
int32x4x2_t vld2q_s32(int32_t const* ptr);          // LD2 {Vt.4S - Vt2.4S},[Xn]
uint8x8x2_t vld2_u8(uint8_t const* ptr);            // LD2 {Vt.8B - Vt2.8B},[Xn]
uint8x16x2_t vld2q_u8(uint8_t const* ptr);          // LD2 {Vt.16B - Vt2.16B},[Xn]
uint16x4x2_t vld2_u16(uint16_t const* ptr);         // LD2 {Vt.4H - Vt2.4H},[Xn]
uint16x8x2_t vld2q_u16(uint16_t const* ptr);        // LD2 {Vt.8H - Vt2.8H},[Xn]
uint32x2x2_t vld2_u32(uint32_t const* ptr);         // LD2 {Vt.2S - Vt2.2S},[Xn]
uint32x4x2_t vld2q_u32(uint32_t const* ptr);        // LD2 {Vt.4S - Vt2.4S},[Xn]
float16x4x2_t vld2_f16(float16_t const* ptr);       // LD2 {Vt.4H - Vt2.4H},[Xn]
float16x8x2_t vld2q_f16(float16_t const* ptr);      // LD2 {Vt.8H - Vt2.8H},[Xn]
float32x2x2_t vld2_f32(float32_t const* ptr);       // LD2 {Vt.2S - Vt2.2S},[Xn]
float32x4x2_t vld2q_f32(float32_t const* ptr);      // LD2 {Vt.4S - Vt2.4S},[Xn]
poly8x8x2_t vld2_p8(poly8_t const* ptr);            // LD2 {Vt.8B - Vt2.8B},[Xn]
poly8x16x2_t vld2q_p8(poly8_t const* ptr);          // LD2 {Vt.16B - Vt2.16B},[Xn]
poly16x4x2_t vld2_p16(poly16_t const* ptr);         // LD2 {Vt.4H - Vt2.4H},[Xn]
poly16x8x2_t vld2q_p16(poly16_t const* ptr);        // LD2 {Vt.8H - Vt2.8H},[Xn]
int64x1x2_t vld2_s64(int64_t const* ptr);           // LD1 {Vt.1D - Vt2.1D},[Xn]
uint64x1x2_t vld2_u64(uint64_t const* ptr);         // LD1 {Vt.1D - Vt2.1D},[Xn]
poly64x1x2_t vld2_p64(poly64_t const* ptr);         // LD1 {Vt.1D - Vt2.1D},[Xn]
int64x2x2_t vld2q_s64(int64_t const* ptr);          // LD2 {Vt.2D - Vt2.2D},[Xn]
uint64x2x2_t vld2q_u64(uint64_t const* ptr);        // LD2 {Vt.2D - Vt2.2D},[Xn]
poly64x2x2_t vld2q_p64(poly64_t const* ptr);        // LD2 {Vt.2D - Vt2.2D},[Xn]
float64x1x2_t vld2_f64(float64_t const* ptr);       // LD1 {Vt.1D - Vt2.1D},[Xn]
float64x2x2_t vld2q_f64(float64_t const* ptr);      // LD2 {Vt.2D - Vt2.2D},[Xn]
int8x8x3_t vld3_s8(int8_t const* ptr);              // LD3 {Vt.8B - Vt3.8B},[Xn]
int8x16x3_t vld3q_s8(int8_t const* ptr);            // LD3 {Vt.16B - Vt3.16B},[Xn]
int16x4x3_t vld3_s16(int16_t const* ptr);           // LD3 {Vt.4H - Vt3.4H},[Xn]
int16x8x3_t vld3q_s16(int16_t const* ptr);          // LD3 {Vt.8H - Vt3.8H},[Xn]
int32x2x3_t vld3_s32(int32_t const* ptr);           // LD3 {Vt.2S - Vt3.2S},[Xn]
int32x4x3_t vld3q_s32(int32_t const* ptr);          // LD3 {Vt.4S - Vt3.4S},[Xn]
uint8x8x3_t vld3_u8(uint8_t const* ptr);            // LD3 {Vt.8B - Vt3.8B},[Xn]
uint8x16x3_t vld3q_u8(uint8_t const* ptr);          // LD3 {Vt.16B - Vt3.16B},[Xn]
uint16x4x3_t vld3_u16(uint16_t const* ptr);         // LD3 {Vt.4H - Vt3.4H},[Xn]
uint16x8x3_t vld3q_u16(uint16_t const* ptr);        // LD3 {Vt.8H - Vt3.8H},[Xn]
uint32x2x3_t vld3_u32(uint32_t const* ptr);         // LD3 {Vt.2S - Vt3.2S},[Xn]
uint32x4x3_t vld3q_u32(uint32_t const* ptr);        // LD3 {Vt.4S - Vt3.4S},[Xn]
float16x4x3_t vld3_f16(float16_t const* ptr);       // LD3 {Vt.4H - Vt3.4H},[Xn]
float16x8x3_t vld3q_f16(float16_t const* ptr);      // LD3 {Vt.8H - Vt3.8H},[Xn]
float32x2x3_t vld3_f32(float32_t const* ptr);       // LD3 {Vt.2S - Vt3.2S},[Xn]
float32x4x3_t vld3q_f32(float32_t const* ptr);      // LD3 {Vt.4S - Vt3.4S},[Xn]
poly8x8x3_t vld3_p8(poly8_t const* ptr);            // LD3 {Vt.8B - Vt3.8B},[Xn]
poly8x16x3_t vld3q_p8(poly8_t const* ptr);          // LD3 {Vt.16B - Vt3.16B},[Xn]
poly16x4x3_t vld3_p16(poly16_t const* ptr);         // LD3 {Vt.4H - Vt3.4H},[Xn]
poly16x8x3_t vld3q_p16(poly16_t const* ptr);        // LD3 {Vt.8H - Vt3.8H},[Xn]
int64x1x3_t vld3_s64(int64_t const* ptr);           // LD1 {Vt.1D - Vt3.1D},[Xn]
uint64x1x3_t vld3_u64(uint64_t const* ptr);         // LD1 {Vt.1D - Vt3.1D},[Xn]
poly64x1x3_t vld3_p64(poly64_t const* ptr);         // LD1 {Vt.1D - Vt3.1D},[Xn]
int64x2x3_t vld3q_s64(int64_t const* ptr);          // LD3 {Vt.2D - Vt3.2D},[Xn]
uint64x2x3_t vld3q_u64(uint64_t const* ptr);        // LD3 {Vt.2D - Vt3.2D},[Xn]
poly64x2x3_t vld3q_p64(poly64_t const* ptr);        // LD3 {Vt.2D - Vt3.2D},[Xn]
float64x1x3_t vld3_f64(float64_t const* ptr);       // LD1 {Vt.1D - Vt3.1D},[Xn]
float64x2x3_t vld3q_f64(float64_t const* ptr);      // LD3 {Vt.2D - Vt3.2D},[Xn]
int8x8x4_t vld4_s8(int8_t const* ptr);              // LD4 {Vt.8B - Vt4.8B},[Xn]
int8x16x4_t vld4q_s8(int8_t const* ptr);            // LD4 {Vt.16B - Vt4.16B},[Xn]
int16x4x4_t vld4_s16(int16_t const* ptr);           // LD4 {Vt.4H - Vt4.4H},[Xn]
int16x8x4_t vld4q_s16(int16_t const* ptr);          // LD4 {Vt.8H - Vt4.8H},[Xn]
int32x2x4_t vld4_s32(int32_t const* ptr);           // LD4 {Vt.2S - Vt4.2S},[Xn]
int32x4x4_t vld4q_s32(int32_t const* ptr);          // LD4 {Vt.4S - Vt4.4S},[Xn]
uint8x8x4_t vld4_u8(uint8_t const* ptr);            // LD4 {Vt.8B - Vt4.8B},[Xn]
uint8x16x4_t vld4q_u8(uint8_t const* ptr);          // LD4 {Vt.16B - Vt4.16B},[Xn]
uint16x4x4_t vld4_u16(uint16_t const* ptr);         // LD4 {Vt.4H - Vt4.4H},[Xn]
uint16x8x4_t vld4q_u16(uint16_t const* ptr);        // LD4 {Vt.8H - Vt4.8H},[Xn]
uint32x2x4_t vld4_u32(uint32_t const* ptr);         // LD4 {Vt.2S - Vt4.2S},[Xn]
uint32x4x4_t vld4q_u32(uint32_t const* ptr);        // LD4 {Vt.4S - Vt4.4S},[Xn]
float16x4x4_t vld4_f16(float16_t const* ptr);       // LD4 {Vt.4H - Vt4.4H},[Xn]
float16x8x4_t vld4q_f16(float16_t const* ptr);      // LD4 {Vt.8H - Vt4.8H},[Xn]
float32x2x4_t vld4_f32(float32_t const* ptr);       // LD4 {Vt.2S - Vt4.2S},[Xn]
float32x4x4_t vld4q_f32(float32_t const* ptr);      // LD4 {Vt.4S - Vt4.4S},[Xn]
poly8x8x4_t vld4_p8(poly8_t const* ptr);            // LD4 {Vt.8B - Vt4.8B},[Xn]
poly8x16x4_t vld4q_p8(poly8_t const* ptr);          // LD4 {Vt.16B - Vt4.16B},[Xn]
poly16x4x4_t vld4_p16(poly16_t const* ptr);         // LD4 {Vt.4H - Vt4.4H},[Xn]
poly16x8x4_t vld4q_p16(poly16_t const* ptr);        // LD4 {Vt.8H - Vt4.8H},[Xn]
int64x1x4_t vld4_s64(int64_t const* ptr);           // LD1 {Vt.1D - Vt4.1D},[Xn]
uint64x1x4_t vld4_u64(uint64_t const* ptr);         // LD1 {Vt.1D - Vt4.1D},[Xn]
poly64x1x4_t vld4_p64(poly64_t const* ptr);         // LD1 {Vt.1D - Vt4.1D},[Xn]
int64x2x4_t vld4q_s64(int64_t const* ptr);          // LD4 {Vt.2D - Vt4.2D},[Xn]
uint64x2x4_t vld4q_u64(uint64_t const* ptr);        // LD4 {Vt.2D - Vt4.2D},[Xn]
poly64x2x4_t vld4q_p64(poly64_t const* ptr);        // LD4 {Vt.2D - Vt4.2D},[Xn]
float64x1x4_t vld4_f64(float64_t const* ptr);       // LD1 {Vt.1D - Vt4.1D},[Xn]
float64x2x4_t vld4q_f64(float64_t const* ptr);      // LD4 {Vt.2D - Vt4.2D},[Xn]
int8x8x2_t vld2_dup_s8(int8_t const* ptr);          // LD2R {Vt.8B - Vt2.8B},[Xn]
int8x16x2_t vld2q_dup_s8(int8_t const* ptr);        // LD2R {Vt.16B - Vt2.16B},[Xn]
int16x4x2_t vld2_dup_s16(int16_t const* ptr);       // LD2R {Vt.4H - Vt2.4H},[Xn]
int16x8x2_t vld2q_dup_s16(int16_t const* ptr);      // LD2R {Vt.8H - Vt2.8H},[Xn]
int32x2x2_t vld2_dup_s32(int32_t const* ptr);       // LD2R {Vt.2S - Vt2.2S},[Xn]
int32x4x2_t vld2q_dup_s32(int32_t const* ptr);      // LD2R {Vt.4S - Vt2.4S},[Xn]
uint8x8x2_t vld2_dup_u8(uint8_t const* ptr);        // LD2R {Vt.8B - Vt2.8B},[Xn]
uint8x16x2_t vld2q_dup_u8(uint8_t const* ptr);      // LD2R {Vt.16B - Vt2.16B},[Xn]
uint16x4x2_t vld2_dup_u16(uint16_t const* ptr);     // LD2R {Vt.4H - Vt2.4H},[Xn]
uint16x8x2_t vld2q_dup_u16(uint16_t const* ptr);    // LD2R {Vt.8H - Vt2.8H},[Xn]
uint32x2x2_t vld2_dup_u32(uint32_t const* ptr);     // LD2R {Vt.2S - Vt2.2S},[Xn]
uint32x4x2_t vld2q_dup_u32(uint32_t const* ptr);    // LD2R {Vt.4S - Vt2.4S},[Xn]
float16x4x2_t vld2_dup_f16(float16_t const* ptr);   // LD2R {Vt.4H - Vt2.4H},[Xn]
float16x8x2_t vld2q_dup_f16(float16_t const* ptr);  // LD2R {Vt.8H - Vt2.8H},[Xn]
float32x2x2_t vld2_dup_f32(float32_t const* ptr);   // LD2R {Vt.2S - Vt2.2S},[Xn]
float32x4x2_t vld2q_dup_f32(float32_t const* ptr);  // LD2R {Vt.4S - Vt2.4S},[Xn]
poly8x8x2_t vld2_dup_p8(poly8_t const* ptr);        // LD2R {Vt.8B - Vt2.8B},[Xn]
poly8x16x2_t vld2q_dup_p8(poly8_t const* ptr);      // LD2R {Vt.16B - Vt2.16B},[Xn]
poly16x4x2_t vld2_dup_p16(poly16_t const* ptr);     // LD2R {Vt.4H - Vt2.4H},[Xn]
poly16x8x2_t vld2q_dup_p16(poly16_t const* ptr);    // LD2R {Vt.8H - Vt2.8H},[Xn]
int64x1x2_t vld2_dup_s64(int64_t const* ptr);       // LD2R {Vt.1D - Vt2.1D},[Xn]
uint64x1x2_t vld2_dup_u64(uint64_t const* ptr);     // LD2R {Vt.1D - Vt2.1D},[Xn]
poly64x1x2_t vld2_dup_p64(poly64_t const* ptr);     // LD2R {Vt.1D - Vt2.1D},[Xn]
int64x2x2_t vld2q_dup_s64(int64_t const* ptr);      // LD2R {Vt.2D - Vt2.2D},[Xn]
uint64x2x2_t vld2q_dup_u64(uint64_t const* ptr);    // LD2R {Vt.2D - Vt2.2D},[Xn]
poly64x2x2_t vld2q_dup_p64(poly64_t const* ptr);    // LD2R {Vt.2D - Vt2.2D},[Xn]
float64x1x2_t vld2_dup_f64(float64_t const* ptr);   // LD2R {Vt.1D - Vt2.1D},[Xn]
float64x2x2_t vld2q_dup_f64(float64_t const* ptr);  // LD2R {Vt.2D - Vt2.2D},[Xn]
int8x8x3_t vld3_dup_s8(int8_t const* ptr);          // LD3R {Vt.8B - Vt3.8B},[Xn]
int8x16x3_t vld3q_dup_s8(int8_t const* ptr);        // LD3R {Vt.16B - Vt3.16B},[Xn]
int16x4x3_t vld3_dup_s16(int16_t const* ptr);       // LD3R {Vt.4H - Vt3.4H},[Xn]
int16x8x3_t vld3q_dup_s16(int16_t const* ptr);      // LD3R {Vt.8H - Vt3.8H},[Xn]
int32x2x3_t vld3_dup_s32(int32_t const* ptr);       // LD3R {Vt.2S - Vt3.2S},[Xn]
int32x4x3_t vld3q_dup_s32(int32_t const* ptr);      // LD3R {Vt.4S - Vt3.4S},[Xn]
uint8x8x3_t vld3_dup_u8(uint8_t const* ptr);        // LD3R {Vt.8B - Vt3.8B},[Xn]
uint8x16x3_t vld3q_dup_u8(uint8_t const* ptr);      // LD3R {Vt.16B - Vt3.16B},[Xn]
uint16x4x3_t vld3_dup_u16(uint16_t const* ptr);     // LD3R {Vt.4H - Vt3.4H},[Xn]
uint16x8x3_t vld3q_dup_u16(uint16_t const* ptr);    // LD3R {Vt.8H - Vt3.8H},[Xn]
uint32x2x3_t vld3_dup_u32(uint32_t const* ptr);     // LD3R {Vt.2S - Vt3.2S},[Xn]
uint32x4x3_t vld3q_dup_u32(uint32_t const* ptr);    // LD3R {Vt.4S - Vt3.4S},[Xn]
float16x4x3_t vld3_dup_f16(float16_t const* ptr);   // LD3R {Vt.4H - Vt3.4H},[Xn]
float16x8x3_t vld3q_dup_f16(float16_t const* ptr);  // LD3R {Vt.8H - Vt3.8H},[Xn]
float32x2x3_t vld3_dup_f32(float32_t const* ptr);   // LD3R {Vt.2S - Vt3.2S},[Xn]
float32x4x3_t vld3q_dup_f32(float32_t const* ptr);  // LD3R {Vt.4S - Vt3.4S},[Xn]
poly8x8x3_t vld3_dup_p8(poly8_t const* ptr);        // LD3R {Vt.8B - Vt3.8B},[Xn]
poly8x16x3_t vld3q_dup_p8(poly8_t const* ptr);      // LD3R {Vt.16B - Vt3.16B},[Xn]
poly16x4x3_t vld3_dup_p16(poly16_t const* ptr);     // LD3R {Vt.4H - Vt3.4H},[Xn]
poly16x8x3_t vld3q_dup_p16(poly16_t const* ptr);    // LD3R {Vt.8H - Vt3.8H},[Xn]
int64x1x3_t vld3_dup_s64(int64_t const* ptr);       // LD3R {Vt.1D - Vt3.1D},[Xn]
uint64x1x3_t vld3_dup_u64(uint64_t const* ptr);     // LD3R {Vt.1D - Vt3.1D},[Xn]
poly64x1x3_t vld3_dup_p64(poly64_t const* ptr);     // LD3R {Vt.1D - Vt3.1D},[Xn]
int64x2x3_t vld3q_dup_s64(int64_t const* ptr);      // LD3R {Vt.2D - Vt3.2D},[Xn]
uint64x2x3_t vld3q_dup_u64(uint64_t const* ptr);    // LD3R {Vt.2D - Vt3.2D},[Xn]
poly64x2x3_t vld3q_dup_p64(poly64_t const* ptr);    // LD3R {Vt.2D - Vt3.2D},[Xn]
float64x1x3_t vld3_dup_f64(float64_t const* ptr);   // LD3R {Vt.1D - Vt3.1D},[Xn]
float64x2x3_t vld3q_dup_f64(float64_t const* ptr);  // LD3R {Vt.2D - Vt3.2D},[Xn]
int8x8x4_t vld4_dup_s8(int8_t const* ptr);          // LD4R {Vt.8B - Vt4.8B},[Xn]
int8x16x4_t vld4q_dup_s8(int8_t const* ptr);        // LD4R {Vt.16B - Vt4.16B},[Xn]
int16x4x4_t vld4_dup_s16(int16_t const* ptr);       // LD4R {Vt.4H - Vt4.4H},[Xn]
int16x8x4_t vld4q_dup_s16(int16_t const* ptr);      // LD4R {Vt.8H - Vt4.8H},[Xn]
int32x2x4_t vld4_dup_s32(int32_t const* ptr);       // LD4R {Vt.2S - Vt4.2S},[Xn]
int32x4x4_t vld4q_dup_s32(int32_t const* ptr);      // LD4R {Vt.4S - Vt4.4S},[Xn]
uint8x8x4_t vld4_dup_u8(uint8_t const* ptr);        // LD4R {Vt.8B - Vt4.8B},[Xn]
uint8x16x4_t vld4q_dup_u8(uint8_t const* ptr);      // LD4R {Vt.16B - Vt4.16B},[Xn]
uint16x4x4_t vld4_dup_u16(uint16_t const* ptr);     // LD4R {Vt.4H - Vt4.4H},[Xn]
uint16x8x4_t vld4q_dup_u16(uint16_t const* ptr);    // LD4R {Vt.8H - Vt4.8H},[Xn]
uint32x2x4_t vld4_dup_u32(uint32_t const* ptr);     // LD4R {Vt.2S - Vt4.2S},[Xn]
uint32x4x4_t vld4q_dup_u32(uint32_t const* ptr);    // LD4R {Vt.4S - Vt4.4S},[Xn]
float16x4x4_t vld4_dup_f16(float16_t const* ptr);   // LD4R {Vt.4H - Vt4.4H},[Xn]
float16x8x4_t vld4q_dup_f16(float16_t const* ptr);  // LD4R {Vt.8H - Vt4.8H},[Xn]
float32x2x4_t vld4_dup_f32(float32_t const* ptr);   // LD4R {Vt.2S - Vt4.2S},[Xn]
float32x4x4_t vld4q_dup_f32(float32_t const* ptr);  // LD4R {Vt.4S - Vt4.4S},[Xn]
poly8x8x4_t vld4_dup_p8(poly8_t const* ptr);        // LD4R {Vt.8B - Vt4.8B},[Xn]
poly8x16x4_t vld4q_dup_p8(poly8_t const* ptr);      // LD4R {Vt.16B - Vt4.16B},[Xn]
poly16x4x4_t vld4_dup_p16(poly16_t const* ptr);     // LD4R {Vt.4H - Vt4.4H},[Xn]
poly16x8x4_t vld4q_dup_p16(poly16_t const* ptr);    // LD4R {Vt.8H - Vt4.8H},[Xn]
int64x1x4_t vld4_dup_s64(int64_t const* ptr);       // LD4R {Vt.1D - Vt4.1D},[Xn]
uint64x1x4_t vld4_dup_u64(uint64_t const* ptr);     // LD4R {Vt.1D - Vt4.1D},[Xn]
poly64x1x4_t vld4_dup_p64(poly64_t const* ptr);     // LD4R {Vt.1D - Vt4.1D},[Xn]
int64x2x4_t vld4q_dup_s64(int64_t const* ptr);      // LD4R {Vt.2D - Vt4.2D},[Xn]
uint64x2x4_t vld4q_dup_u64(uint64_t const* ptr);    // LD4R {Vt.2D - Vt4.2D},[Xn]
poly64x2x4_t vld4q_dup_p64(poly64_t const* ptr);    // LD4R {Vt.2D - Vt4.2D},[Xn]
float64x1x4_t vld4_dup_f64(float64_t const* ptr);   // LD4R {Vt.1D - Vt4.1D},[Xn]
float64x2x4_t vld4q_dup_f64(float64_t const* ptr);  // LD4R {Vt.2D - Vt4.2D},[Xn]
void vst2_s8(int8_t* ptr, int8x8x2_t val);          // ST2 {Vt.8B - Vt2.8B},[Xn]
void vst2q_s8(int8_t* ptr, int8x16x2_t val);        // ST2 {Vt.16B - Vt2.16B},[Xn]
void vst2_s16(int16_t* ptr, int16x4x2_t val);       // ST2 {Vt.4H - Vt2.4H},[Xn]
void vst2q_s16(int16_t* ptr, int16x8x2_t val);      // ST2 {Vt.8H - Vt2.8H},[Xn]
void vst2_s32(int32_t* ptr, int32x2x2_t val);       // ST2 {Vt.2S - Vt2.2S},[Xn]
void vst2q_s32(int32_t* ptr, int32x4x2_t val);      // ST2 {Vt.4S - Vt2.4S},[Xn]
void vst2_u8(uint8_t* ptr, uint8x8x2_t val);        // ST2 {Vt.8B - Vt2.8B},[Xn]
void vst2q_u8(uint8_t* ptr, uint8x16x2_t val);      // ST2 {Vt.16B - Vt2.16B},[Xn]
void vst2_u16(uint16_t* ptr, uint16x4x2_t val);     // ST2 {Vt.4H - Vt2.4H},[Xn]
void vst2q_u16(uint16_t* ptr, uint16x8x2_t val);    // ST2 {Vt.8H - Vt2.8H},[Xn]
void vst2_u32(uint32_t* ptr, uint32x2x2_t val);     // ST2 {Vt.2S - Vt2.2S},[Xn]
void vst2q_u32(uint32_t* ptr, uint32x4x2_t val);    // ST2 {Vt.4S - Vt2.4S},[Xn]
void vst2_f16(float16_t* ptr, float16x4x2_t val);   // ST2 {Vt.4H - Vt2.4H},[Xn]
void vst2q_f16(float16_t* ptr, float16x8x2_t val);  // ST2 {Vt.8H - Vt2.8H},[Xn]
void vst2_f32(float32_t* ptr, float32x2x2_t val);   // ST2 {Vt.2S - Vt2.2S},[Xn]
void vst2q_f32(float32_t* ptr, float32x4x2_t val);  // ST2 {Vt.4S - Vt2.4S},[Xn]
void vst2_p8(poly8_t* ptr, poly8x8x2_t val);        // ST2 {Vt.8B - Vt2.8B},[Xn]
void vst2q_p8(poly8_t* ptr, poly8x16x2_t val);      // ST2 {Vt.16B - Vt2.16B},[Xn]
void vst2_p16(poly16_t* ptr, poly16x4x2_t val);     // ST2 {Vt.4H - Vt2.4H},[Xn]
void vst2q_p16(poly16_t* ptr, poly16x8x2_t val);    // ST2 {Vt.8H - Vt2.8H},[Xn]
void vst2_s64(int64_t* ptr, int64x1x2_t val);       // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst2_u64(uint64_t* ptr, uint64x1x2_t val);     // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst2_p64(poly64_t* ptr, poly64x1x2_t val);     // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst2q_s64(int64_t* ptr, int64x2x2_t val);      // ST2 {Vt.2D - Vt2.2D},[Xn]
void vst2q_u64(uint64_t* ptr, uint64x2x2_t val);    // ST2 {Vt.2D - Vt2.2D},[Xn]
void vst2q_p64(poly64_t* ptr, poly64x2x2_t val);    // ST2 {Vt.2D - Vt2.2D},[Xn]
void vst2_f64(float64_t* ptr, float64x1x2_t val);   // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst2q_f64(float64_t* ptr, float64x2x2_t val);  // ST2 {Vt.2D - Vt2.2D},[Xn]
void vst3_s8(int8_t* ptr, int8x8x3_t val);          // ST3 {Vt.8B - Vt3.8B},[Xn]
void vst3q_s8(int8_t* ptr, int8x16x3_t val);        // ST3 {Vt.16B - Vt3.16B},[Xn]
void vst3_s16(int16_t* ptr, int16x4x3_t val);       // ST3 {Vt.4H - Vt3.4H},[Xn]
void vst3q_s16(int16_t* ptr, int16x8x3_t val);      // ST3 {Vt.8H - Vt3.8H},[Xn]
void vst3_s32(int32_t* ptr, int32x2x3_t val);       // ST3 {Vt.2S - Vt3.2S},[Xn]
void vst3q_s32(int32_t* ptr, int32x4x3_t val);      // ST3 {Vt.4S - Vt3.4S},[Xn]
void vst3_u8(uint8_t* ptr, uint8x8x3_t val);        // ST3 {Vt.8B - Vt3.8B},[Xn]
void vst3q_u8(uint8_t* ptr, uint8x16x3_t val);      // ST3 {Vt.16B - Vt3.16B},[Xn]
void vst3_u16(uint16_t* ptr, uint16x4x3_t val);     // ST3 {Vt.4H - Vt3.4H},[Xn]
void vst3q_u16(uint16_t* ptr, uint16x8x3_t val);    // ST3 {Vt.8H - Vt3.8H},[Xn]
void vst3_u32(uint32_t* ptr, uint32x2x3_t val);     // ST3 {Vt.2S - Vt3.2S},[Xn]
void vst3q_u32(uint32_t* ptr, uint32x4x3_t val);    // ST3 {Vt.4S - Vt3.4S},[Xn]
void vst3_f16(float16_t* ptr, float16x4x3_t val);   // ST3 {Vt.4H - Vt3.4H},[Xn]
void vst3q_f16(float16_t* ptr, float16x8x3_t val);  // ST3 {Vt.8H - Vt3.8H},[Xn]
void vst3_f32(float32_t* ptr, float32x2x3_t val);   // ST3 {Vt.2S - Vt3.2S},[Xn]
void vst3q_f32(float32_t* ptr, float32x4x3_t val);  // ST3 {Vt.4S - Vt3.4S},[Xn]
void vst3_p8(poly8_t* ptr, poly8x8x3_t val);        // ST3 {Vt.8B - Vt3.8B},[Xn]
void vst3q_p8(poly8_t* ptr, poly8x16x3_t val);      // ST3 {Vt.16B - Vt3.16B},[Xn]
void vst3_p16(poly16_t* ptr, poly16x4x3_t val);     // ST3 {Vt.4H - Vt3.4H},[Xn]
void vst3q_p16(poly16_t* ptr, poly16x8x3_t val);    // ST3 {Vt.8H - Vt3.8H},[Xn]
void vst3_s64(int64_t* ptr, int64x1x3_t val);       // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst3_u64(uint64_t* ptr, uint64x1x3_t val);     // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst3_p64(poly64_t* ptr, poly64x1x3_t val);     // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst3q_s64(int64_t* ptr, int64x2x3_t val);      // ST3 {Vt.2D - Vt3.2D},[Xn]
void vst3q_u64(uint64_t* ptr, uint64x2x3_t val);    // ST3 {Vt.2D - Vt3.2D},[Xn]
void vst3q_p64(poly64_t* ptr, poly64x2x3_t val);    // ST3 {Vt.2D - Vt3.2D},[Xn]
void vst3_f64(float64_t* ptr, float64x1x3_t val);   // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst3q_f64(float64_t* ptr, float64x2x3_t val);  // ST3 {Vt.2D - Vt3.2D},[Xn]
void vst4_s8(int8_t* ptr, int8x8x4_t val);          // ST4 {Vt.8B - Vt4.8B},[Xn]
void vst4q_s8(int8_t* ptr, int8x16x4_t val);        // ST4 {Vt.16B - Vt4.16B},[Xn]
void vst4_s16(int16_t* ptr, int16x4x4_t val);       // ST4 {Vt.4H - Vt4.4H},[Xn]
void vst4q_s16(int16_t* ptr, int16x8x4_t val);      // ST4 {Vt.8H - Vt4.8H},[Xn]
void vst4_s32(int32_t* ptr, int32x2x4_t val);       // ST4 {Vt.2S - Vt4.2S},[Xn]
void vst4q_s32(int32_t* ptr, int32x4x4_t val);      // ST4 {Vt.4S - Vt4.4S},[Xn]
void vst4_u8(uint8_t* ptr, uint8x8x4_t val);        // ST4 {Vt.8B - Vt4.8B},[Xn]
void vst4q_u8(uint8_t* ptr, uint8x16x4_t val);      // ST4 {Vt.16B - Vt4.16B},[Xn]
void vst4_u16(uint16_t* ptr, uint16x4x4_t val);     // ST4 {Vt.4H - Vt4.4H},[Xn]
void vst4q_u16(uint16_t* ptr, uint16x8x4_t val);    // ST4 {Vt.8H - Vt4.8H},[Xn]
void vst4_u32(uint32_t* ptr, uint32x2x4_t val);     // ST4 {Vt.2S - Vt4.2S},[Xn]
void vst4q_u32(uint32_t* ptr, uint32x4x4_t val);    // ST4 {Vt.4S - Vt4.4S},[Xn]
void vst4_f16(float16_t* ptr, float16x4x4_t val);   // ST4 {Vt.4H - Vt4.4H},[Xn]
void vst4q_f16(float16_t* ptr, float16x8x4_t val);  // ST4 {Vt.8H - Vt4.8H},[Xn]
void vst4_f32(float32_t* ptr, float32x2x4_t val);   // ST4 {Vt.2S - Vt4.2S},[Xn]
void vst4q_f32(float32_t* ptr, float32x4x4_t val);  // ST4 {Vt.4S - Vt4.4S},[Xn]
void vst4_p8(poly8_t* ptr, poly8x8x4_t val);        // ST4 {Vt.8B - Vt4.8B},[Xn]
void vst4q_p8(poly8_t* ptr, poly8x16x4_t val);      // ST4 {Vt.16B - Vt4.16B},[Xn]
void vst4_p16(poly16_t* ptr, poly16x4x4_t val);     // ST4 {Vt.4H - Vt4.4H},[Xn]
void vst4q_p16(poly16_t* ptr, poly16x8x4_t val);    // ST4 {Vt.8H - Vt4.8H},[Xn]
void vst4_s64(int64_t* ptr, int64x1x4_t val);       // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst4_u64(uint64_t* ptr, uint64x1x4_t val);     // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst4_p64(poly64_t* ptr, poly64x1x4_t val);     // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst4q_s64(int64_t* ptr, int64x2x4_t val);      // ST4 {Vt.2D - Vt4.2D},[Xn]
void vst4q_u64(uint64_t* ptr, uint64x2x4_t val);    // ST4 {Vt.2D - Vt4.2D},[Xn]
void vst4q_p64(poly64_t* ptr, poly64x2x4_t val);    // ST4 {Vt.2D - Vt4.2D},[Xn]
void vst4_f64(float64_t* ptr, float64x1x4_t val);   // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst4q_f64(float64_t* ptr, float64x2x4_t val);  // ST4 {Vt.2D - Vt4.2D},[Xn]
int16x4x2_t vld2_lane_s16(
    int16_t const* ptr, int16x4x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
int16x8x2_t vld2q_lane_s16(
    int16_t const* ptr, int16x8x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
int32x2x2_t vld2_lane_s32(
    int32_t const* ptr, int32x2x2_t src, const int lane);  // LD2 {Vt.s - Vt2.s}[lane],[Xn]
int32x4x2_t vld2q_lane_s32(
    int32_t const* ptr, int32x4x2_t src, const int lane);  // LD2 {Vt.s - Vt2.s}[lane],[Xn]
uint16x4x2_t vld2_lane_u16(
    uint16_t const* ptr, uint16x4x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
uint16x8x2_t vld2q_lane_u16(
    uint16_t const* ptr, uint16x8x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
uint32x2x2_t vld2_lane_u32(
    uint32_t const* ptr, uint32x2x2_t src, const int lane);  // LD2 {Vt.s - Vt2.s}[lane],[Xn]
uint32x4x2_t vld2q_lane_u32(
    uint32_t const* ptr, uint32x4x2_t src, const int lane);  // LD2 {Vt.s - Vt2.s}[lane],[Xn]
float16x4x2_t vld2_lane_f16(
    float16_t const* ptr, float16x4x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
float16x8x2_t vld2q_lane_f16(
    float16_t const* ptr, float16x8x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
float32x2x2_t vld2_lane_f32(
    float32_t const* ptr, float32x2x2_t src, const int lane);  // LD2 {Vt.s - Vt2.s}[lane],[Xn]
float32x4x2_t vld2q_lane_f32(
    float32_t const* ptr, float32x4x2_t src, const int lane);  // LD2 {Vt.s - Vt2.s}[lane],[Xn]
poly16x4x2_t vld2_lane_p16(
    poly16_t const* ptr, poly16x4x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
poly16x8x2_t vld2q_lane_p16(
    poly16_t const* ptr, poly16x8x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
int8x8x2_t vld2_lane_s8(
    int8_t const* ptr, int8x8x2_t src, const int lane);  // LD2 {Vt.b - Vt2.b}[lane],[Xn]
uint8x8x2_t vld2_lane_u8(
    uint8_t const* ptr, uint8x8x2_t src, const int lane);  // LD2 {Vt.b - Vt2.b}[lane],[Xn]
poly8x8x2_t vld2_lane_p8(
    poly8_t const* ptr, poly8x8x2_t src, const int lane);  // LD2 {Vt.b - Vt2.b}[lane],[Xn]
int8x16x2_t vld2q_lane_s8(
    int8_t const* ptr, int8x16x2_t src, const int lane);  // LD2 {Vt.b - Vt2.b}[lane],[Xn]
uint8x16x2_t vld2q_lane_u8(
    uint8_t const* ptr, uint8x16x2_t src, const int lane);  // LD2 {Vt.b - Vt2.b}[lane],[Xn]
poly8x16x2_t vld2q_lane_p8(
    poly8_t const* ptr, poly8x16x2_t src, const int lane);  // LD2 {Vt.b - Vt2.b}[lane],[Xn]
int64x1x2_t vld2_lane_s64(
    int64_t const* ptr, int64x1x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
int64x2x2_t vld2q_lane_s64(
    int64_t const* ptr, int64x2x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
uint64x1x2_t vld2_lane_u64(
    uint64_t const* ptr, uint64x1x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
uint64x2x2_t vld2q_lane_u64(
    uint64_t const* ptr, uint64x2x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
poly64x1x2_t vld2_lane_p64(
    poly64_t const* ptr, poly64x1x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
poly64x2x2_t vld2q_lane_p64(
    poly64_t const* ptr, poly64x2x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
float64x1x2_t vld2_lane_f64(
    float64_t const* ptr, float64x1x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
float64x2x2_t vld2q_lane_f64(
    float64_t const* ptr, float64x2x2_t src, const int lane);  // LD2 {Vt.d - Vt2.d}[lane],[Xn]
int16x4x3_t vld3_lane_s16(
    int16_t const* ptr, int16x4x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
int16x8x3_t vld3q_lane_s16(
    int16_t const* ptr, int16x8x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
int32x2x3_t vld3_lane_s32(
    int32_t const* ptr, int32x2x3_t src, const int lane);  // LD3 {Vt.s - Vt3.s}[lane],[Xn]
int32x4x3_t vld3q_lane_s32(
    int32_t const* ptr, int32x4x3_t src, const int lane);  // LD3 {Vt.s - Vt3.s}[lane],[Xn]
uint16x4x3_t vld3_lane_u16(
    uint16_t const* ptr, uint16x4x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
uint16x8x3_t vld3q_lane_u16(
    uint16_t const* ptr, uint16x8x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
uint32x2x3_t vld3_lane_u32(
    uint32_t const* ptr, uint32x2x3_t src, const int lane);  // LD3 {Vt.s - Vt3.s}[lane],[Xn]
uint32x4x3_t vld3q_lane_u32(
    uint32_t const* ptr, uint32x4x3_t src, const int lane);  // LD3 {Vt.s - Vt3.s}[lane],[Xn]
float16x4x3_t vld3_lane_f16(
    float16_t const* ptr, float16x4x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
float16x8x3_t vld3q_lane_f16(
    float16_t const* ptr, float16x8x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
float32x2x3_t vld3_lane_f32(
    float32_t const* ptr, float32x2x3_t src, const int lane);  // LD3 {Vt.s - Vt3.s}[lane],[Xn]
float32x4x3_t vld3q_lane_f32(
    float32_t const* ptr, float32x4x3_t src, const int lane);  // LD3 {Vt.s - Vt3.s}[lane],[Xn]
poly16x4x3_t vld3_lane_p16(
    poly16_t const* ptr, poly16x4x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
poly16x8x3_t vld3q_lane_p16(
    poly16_t const* ptr, poly16x8x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
int8x8x3_t vld3_lane_s8(
    int8_t const* ptr, int8x8x3_t src, const int lane);  // LD3 {Vt.b - Vt3.b}[lane],[Xn]
uint8x8x3_t vld3_lane_u8(
    uint8_t const* ptr, uint8x8x3_t src, const int lane);  // LD3 {Vt.b - Vt3.b}[lane],[Xn]
poly8x8x3_t vld3_lane_p8(
    poly8_t const* ptr, poly8x8x3_t src, const int lane);  // LD3 {Vt.b - Vt3.b}[lane],[Xn]
int8x16x3_t vld3q_lane_s8(
    int8_t const* ptr, int8x16x3_t src, const int lane);  // LD3 {Vt.b - Vt3.b}[lane],[Xn]
uint8x16x3_t vld3q_lane_u8(
    uint8_t const* ptr, uint8x16x3_t src, const int lane);  // LD3 {Vt.b - Vt3.b}[lane],[Xn]
poly8x16x3_t vld3q_lane_p8(
    poly8_t const* ptr, poly8x16x3_t src, const int lane);  // LD3 {Vt.b - Vt3.b}[lane],[Xn]
int64x1x3_t vld3_lane_s64(
    int64_t const* ptr, int64x1x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
int64x2x3_t vld3q_lane_s64(
    int64_t const* ptr, int64x2x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
uint64x1x3_t vld3_lane_u64(
    uint64_t const* ptr, uint64x1x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
uint64x2x3_t vld3q_lane_u64(
    uint64_t const* ptr, uint64x2x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
poly64x1x3_t vld3_lane_p64(
    poly64_t const* ptr, poly64x1x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
poly64x2x3_t vld3q_lane_p64(
    poly64_t const* ptr, poly64x2x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
float64x1x3_t vld3_lane_f64(
    float64_t const* ptr, float64x1x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
float64x2x3_t vld3q_lane_f64(
    float64_t const* ptr, float64x2x3_t src, const int lane);  // LD3 {Vt.d - Vt3.d}[lane],[Xn]
int16x4x4_t vld4_lane_s16(
    int16_t const* ptr, int16x4x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
int16x8x4_t vld4q_lane_s16(
    int16_t const* ptr, int16x8x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
int32x2x4_t vld4_lane_s32(
    int32_t const* ptr, int32x2x4_t src, const int lane);  // LD4 {Vt.s - Vt4.s}[lane],[Xn]
int32x4x4_t vld4q_lane_s32(
    int32_t const* ptr, int32x4x4_t src, const int lane);  // LD4 {Vt.s - Vt4.s}[lane],[Xn]
uint16x4x4_t vld4_lane_u16(
    uint16_t const* ptr, uint16x4x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
uint16x8x4_t vld4q_lane_u16(
    uint16_t const* ptr, uint16x8x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
uint32x2x4_t vld4_lane_u32(
    uint32_t const* ptr, uint32x2x4_t src, const int lane);  // LD4 {Vt.s - Vt4.s}[lane],[Xn]
uint32x4x4_t vld4q_lane_u32(
    uint32_t const* ptr, uint32x4x4_t src, const int lane);  // LD4 {Vt.s - Vt4.s}[lane],[Xn]
float16x4x4_t vld4_lane_f16(
    float16_t const* ptr, float16x4x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
float16x8x4_t vld4q_lane_f16(
    float16_t const* ptr, float16x8x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
float32x2x4_t vld4_lane_f32(
    float32_t const* ptr, float32x2x4_t src, const int lane);  // LD4 {Vt.s - Vt4.s}[lane],[Xn]
float32x4x4_t vld4q_lane_f32(
    float32_t const* ptr, float32x4x4_t src, const int lane);  // LD4 {Vt.s - Vt4.s}[lane],[Xn]
poly16x4x4_t vld4_lane_p16(
    poly16_t const* ptr, poly16x4x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
poly16x8x4_t vld4q_lane_p16(
    poly16_t const* ptr, poly16x8x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
int8x8x4_t vld4_lane_s8(
    int8_t const* ptr, int8x8x4_t src, const int lane);  // LD4 {Vt.b - Vt4.b}[lane],[Xn]
uint8x8x4_t vld4_lane_u8(
    uint8_t const* ptr, uint8x8x4_t src, const int lane);  // LD4 {Vt.b - Vt4.b}[lane],[Xn]
poly8x8x4_t vld4_lane_p8(
    poly8_t const* ptr, poly8x8x4_t src, const int lane);  // LD4 {Vt.b - Vt4.b}[lane],[Xn]
int8x16x4_t vld4q_lane_s8(
    int8_t const* ptr, int8x16x4_t src, const int lane);  // LD4 {Vt.b - Vt4.b}[lane],[Xn]
uint8x16x4_t vld4q_lane_u8(
    uint8_t const* ptr, uint8x16x4_t src, const int lane);  // LD4 {Vt.b - Vt4.b}[lane],[Xn]
poly8x16x4_t vld4q_lane_p8(
    poly8_t const* ptr, poly8x16x4_t src, const int lane);  // LD4 {Vt.b - Vt4.b}[lane],[Xn]
int64x1x4_t vld4_lane_s64(
    int64_t const* ptr, int64x1x4_t src, const int lane);  // LD4 {Vt.d - Vt4.d}[lane],[Xn]
int64x2x4_t vld4q_lane_s64(
    int64_t const* ptr, int64x2x4_t src, const int lane);  // LD4 {Vt.d - Vt4.d}[lane],[Xn]
uint64x1x4_t vld4_lane_u64(
    uint64_t const* ptr, uint64x1x4_t src, const int lane);  // LD4 {Vt.d - Vt4.d}[lane],[Xn]
uint64x2x4_t vld4q_lane_u64(
    uint64_t const* ptr, uint64x2x4_t src, const int lane);  // LD4 {Vt.d - Vt4.d}[lane],[Xn]
poly64x1x4_t vld4_lane_p64(
    poly64_t const* ptr, poly64x1x4_t src, const int lane);  // LD4 {Vt.d - Vt4.d}[lane],[Xn]
poly64x2x4_t vld4q_lane_p64(
    poly64_t const* ptr, poly64x2x4_t src, const int lane);  // LD4 {Vt.d - Vt4.d}[lane],[Xn]
float64x1x4_t vld4_lane_f64(
    float64_t const* ptr, float64x1x4_t src, const int lane);  // LD4 {Vt.d - Vt4.d}[lane],[Xn]
float64x2x4_t vld4q_lane_f64(
    float64_t const* ptr, float64x2x4_t src, const int lane);       // LD4 {Vt.d - Vt4.d}[lane],[Xn]
void vst2_lane_s8(int8_t* ptr, int8x8x2_t val, const int lane);     // ST2 {Vt.b - Vt2.b}[lane],[Xn]
void vst2_lane_u8(uint8_t* ptr, uint8x8x2_t val, const int lane);   // ST2 {Vt.b - Vt2.b}[lane],[Xn]
void vst2_lane_p8(poly8_t* ptr, poly8x8x2_t val, const int lane);   // ST2 {Vt.b - Vt2.b}[lane],[Xn]
void vst3_lane_s8(int8_t* ptr, int8x8x3_t val, const int lane);     // ST3 {Vt.b - Vt3.b}[lane],[Xn]
void vst3_lane_u8(uint8_t* ptr, uint8x8x3_t val, const int lane);   // ST3 {Vt.b - Vt3.b}[lane],[Xn]
void vst3_lane_p8(poly8_t* ptr, poly8x8x3_t val, const int lane);   // ST3 {Vt.b - Vt3.b}[lane],[Xn]
void vst4_lane_s8(int8_t* ptr, int8x8x4_t val, const int lane);     // ST4 {Vt.b - Vt4.b}[lane],[Xn]
void vst4_lane_u8(uint8_t* ptr, uint8x8x4_t val, const int lane);   // ST4 {Vt.b - Vt4.b}[lane],[Xn]
void vst4_lane_p8(poly8_t* ptr, poly8x8x4_t val, const int lane);   // ST4 {Vt.b - Vt4.b}[lane],[Xn]
void vst2_lane_s16(int16_t* ptr, int16x4x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2q_lane_s16(
    int16_t* ptr, int16x8x2_t val, const int lane);                 // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2_lane_s32(int32_t* ptr, int32x2x2_t val, const int lane);  // ST2 {Vt.s - Vt2.s}[lane],[Xn]
void vst2q_lane_s32(
    int32_t* ptr, int32x4x2_t val, const int lane);  // ST2 {Vt.s - Vt2.s}[lane],[Xn]
void vst2_lane_u16(
    uint16_t* ptr, uint16x4x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2q_lane_u16(
    uint16_t* ptr, uint16x8x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2_lane_u32(
    uint32_t* ptr, uint32x2x2_t val, const int lane);  // ST2 {Vt.s - Vt2.s}[lane],[Xn]
void vst2q_lane_u32(
    uint32_t* ptr, uint32x4x2_t val, const int lane);  // ST2 {Vt.s - Vt2.s}[lane],[Xn]
void vst2_lane_f16(
    float16_t* ptr, float16x4x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2q_lane_f16(
    float16_t* ptr, float16x8x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2_lane_f32(
    float32_t* ptr, float32x2x2_t val, const int lane);  // ST2 {Vt.s - Vt2.s}[lane],[Xn]
void vst2q_lane_f32(
    float32_t* ptr, float32x4x2_t val, const int lane);  // ST2 {Vt.s - Vt2.s}[lane],[Xn]
void vst2_lane_p16(
    poly16_t* ptr, poly16x4x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2q_lane_p16(
    poly16_t* ptr, poly16x8x2_t val, const int lane);              // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2q_lane_s8(int8_t* ptr, int8x16x2_t val, const int lane);  // ST2 {Vt.b - Vt2.b}[lane],[Xn]
void vst2q_lane_u8(
    uint8_t* ptr, uint8x16x2_t val, const int lane);  // ST2 {Vt.b - Vt2.b}[lane],[Xn]
void vst2q_lane_p8(
    poly8_t* ptr, poly8x16x2_t val, const int lane);                // ST2 {Vt.b - Vt2.b}[lane],[Xn]
void vst2_lane_s64(int64_t* ptr, int64x1x2_t val, const int lane);  // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst2q_lane_s64(
    int64_t* ptr, int64x2x2_t val, const int lane);  // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst2_lane_u64(
    uint64_t* ptr, uint64x1x2_t val, const int lane);  // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst2q_lane_u64(
    uint64_t* ptr, uint64x2x2_t val, const int lane);  // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst2_lane_p64(
    poly64_t* ptr, poly64x1x2_t val, const int lane);  // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst2q_lane_p64(
    poly64_t* ptr, poly64x2x2_t val, const int lane);  // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst2_lane_f64(
    float64_t* ptr, float64x1x2_t val, const int lane);  // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst2q_lane_f64(
    float64_t* ptr, float64x2x2_t val, const int lane);             // ST2 {Vt.d - Vt2.d}[lane],[Xn]
void vst3_lane_s16(int16_t* ptr, int16x4x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3q_lane_s16(
    int16_t* ptr, int16x8x3_t val, const int lane);                 // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3_lane_s32(int32_t* ptr, int32x2x3_t val, const int lane);  // ST3 {Vt.s - Vt3.s}[lane],[Xn]
void vst3q_lane_s32(
    int32_t* ptr, int32x4x3_t val, const int lane);  // ST3 {Vt.s - Vt3.s}[lane],[Xn]
void vst3_lane_u16(
    uint16_t* ptr, uint16x4x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3q_lane_u16(
    uint16_t* ptr, uint16x8x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3_lane_u32(
    uint32_t* ptr, uint32x2x3_t val, const int lane);  // ST3 {Vt.s - Vt3.s}[lane],[Xn]
void vst3q_lane_u32(
    uint32_t* ptr, uint32x4x3_t val, const int lane);  // ST3 {Vt.s - Vt3.s}[lane],[Xn]
void vst3_lane_f16(
    float16_t* ptr, float16x4x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3q_lane_f16(
    float16_t* ptr, float16x8x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3_lane_f32(
    float32_t* ptr, float32x2x3_t val, const int lane);  // ST3 {Vt.s - Vt3.s}[lane],[Xn]
void vst3q_lane_f32(
    float32_t* ptr, float32x4x3_t val, const int lane);  // ST3 {Vt.s - Vt3.s}[lane],[Xn]
void vst3_lane_p16(
    poly16_t* ptr, poly16x4x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3q_lane_p16(
    poly16_t* ptr, poly16x8x3_t val, const int lane);              // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3q_lane_s8(int8_t* ptr, int8x16x3_t val, const int lane);  // ST3 {Vt.b - Vt3.b}[lane],[Xn]
void vst3q_lane_u8(
    uint8_t* ptr, uint8x16x3_t val, const int lane);  // ST3 {Vt.b - Vt3.b}[lane],[Xn]
void vst3q_lane_p8(
    poly8_t* ptr, poly8x16x3_t val, const int lane);                // ST3 {Vt.b - Vt3.b}[lane],[Xn]
void vst3_lane_s64(int64_t* ptr, int64x1x3_t val, const int lane);  // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst3q_lane_s64(
    int64_t* ptr, int64x2x3_t val, const int lane);  // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst3_lane_u64(
    uint64_t* ptr, uint64x1x3_t val, const int lane);  // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst3q_lane_u64(
    uint64_t* ptr, uint64x2x3_t val, const int lane);  // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst3_lane_p64(
    poly64_t* ptr, poly64x1x3_t val, const int lane);  // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst3q_lane_p64(
    poly64_t* ptr, poly64x2x3_t val, const int lane);  // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst3_lane_f64(
    float64_t* ptr, float64x1x3_t val, const int lane);  // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst3q_lane_f64(
    float64_t* ptr, float64x2x3_t val, const int lane);             // ST3 {Vt.d - Vt3.d}[lane],[Xn]
void vst4_lane_s16(int16_t* ptr, int16x4x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4q_lane_s16(
    int16_t* ptr, int16x8x4_t val, const int lane);                 // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4_lane_s32(int32_t* ptr, int32x2x4_t val, const int lane);  // ST4 {Vt.s - Vt4.s}[lane],[Xn]
void vst4q_lane_s32(
    int32_t* ptr, int32x4x4_t val, const int lane);  // ST4 {Vt.s - Vt4.s}[lane],[Xn]
void vst4_lane_u16(
    uint16_t* ptr, uint16x4x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4q_lane_u16(
    uint16_t* ptr, uint16x8x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4_lane_u32(
    uint32_t* ptr, uint32x2x4_t val, const int lane);  // ST4 {Vt.s - Vt4.s}[lane],[Xn]
void vst4q_lane_u32(
    uint32_t* ptr, uint32x4x4_t val, const int lane);  // ST4 {Vt.s - Vt4.s}[lane],[Xn]
void vst4_lane_f16(
    float16_t* ptr, float16x4x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4q_lane_f16(
    float16_t* ptr, float16x8x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4_lane_f32(
    float32_t* ptr, float32x2x4_t val, const int lane);  // ST4 {Vt.s - Vt4.s}[lane],[Xn]
void vst4q_lane_f32(
    float32_t* ptr, float32x4x4_t val, const int lane);  // ST4 {Vt.s - Vt4.s}[lane],[Xn]
void vst4_lane_p16(
    poly16_t* ptr, poly16x4x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4q_lane_p16(
    poly16_t* ptr, poly16x8x4_t val, const int lane);              // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4q_lane_s8(int8_t* ptr, int8x16x4_t val, const int lane);  // ST4 {Vt.b - Vt4.b}[lane],[Xn]
void vst4q_lane_u8(
    uint8_t* ptr, uint8x16x4_t val, const int lane);  // ST4 {Vt.b - Vt4.b}[lane],[Xn]
void vst4q_lane_p8(
    poly8_t* ptr, poly8x16x4_t val, const int lane);                // ST4 {Vt.b - Vt4.b}[lane],[Xn]
void vst4_lane_s64(int64_t* ptr, int64x1x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst4q_lane_s64(
    int64_t* ptr, int64x2x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst4_lane_u64(
    uint64_t* ptr, uint64x1x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst4q_lane_u64(
    uint64_t* ptr, uint64x2x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst4_lane_p64(
    poly64_t* ptr, poly64x1x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst4q_lane_p64(
    poly64_t* ptr, poly64x2x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst4_lane_f64(
    float64_t* ptr, float64x1x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst4q_lane_f64(
    float64_t* ptr, float64x2x4_t val, const int lane);  // ST4 {Vt.d - Vt4.d}[lane],[Xn]
void vst1_s8_x2(int8_t* ptr, int8x8x2_t val);            // ST1 {Vt.8B - Vt2.8B},[Xn]
void vst1q_s8_x2(int8_t* ptr, int8x16x2_t val);          // ST1 {Vt.16B - Vt2.16B},[Xn]
void vst1_s16_x2(int16_t* ptr, int16x4x2_t val);         // ST1 {Vt.4H - Vt2.4H},[Xn]
void vst1q_s16_x2(int16_t* ptr, int16x8x2_t val);        // ST1 {Vt.8H - Vt2.8H},[Xn]
void vst1_s32_x2(int32_t* ptr, int32x2x2_t val);         // ST1 {Vt.2S - Vt2.2S},[Xn]
void vst1q_s32_x2(int32_t* ptr, int32x4x2_t val);        // ST1 {Vt.4S - Vt2.4S},[Xn]
void vst1_u8_x2(uint8_t* ptr, uint8x8x2_t val);          // ST1 {Vt.8B - Vt2.8B},[Xn]
void vst1q_u8_x2(uint8_t* ptr, uint8x16x2_t val);        // ST1 {Vt.16B - Vt2.16B},[Xn]
void vst1_u16_x2(uint16_t* ptr, uint16x4x2_t val);       // ST1 {Vt.4H - Vt2.4H},[Xn]
void vst1q_u16_x2(uint16_t* ptr, uint16x8x2_t val);      // ST1 {Vt.8H - Vt2.8H},[Xn]
void vst1_u32_x2(uint32_t* ptr, uint32x2x2_t val);       // ST1 {Vt.2S - Vt2.2S},[Xn]
void vst1q_u32_x2(uint32_t* ptr, uint32x4x2_t val);      // ST1 {Vt.4S - Vt2.4S},[Xn]
void vst1_f16_x2(float16_t* ptr, float16x4x2_t val);     // ST1 {Vt.4H - Vt2.4H},[Xn]
void vst1q_f16_x2(float16_t* ptr, float16x8x2_t val);    // ST1 {Vt.8H - Vt2.8H},[Xn]
void vst1_f32_x2(float32_t* ptr, float32x2x2_t val);     // ST1 {Vt.2S - Vt2.2S},[Xn]
void vst1q_f32_x2(float32_t* ptr, float32x4x2_t val);    // ST1 {Vt.4S - Vt2.4S},[Xn]
void vst1_p8_x2(poly8_t* ptr, poly8x8x2_t val);          // ST1 {Vt.8B - Vt2.8B},[Xn]
void vst1q_p8_x2(poly8_t* ptr, poly8x16x2_t val);        // ST1 {Vt.16B - Vt2.16B},[Xn]
void vst1_p16_x2(poly16_t* ptr, poly16x4x2_t val);       // ST1 {Vt.4H - Vt2.4H},[Xn]
void vst1q_p16_x2(poly16_t* ptr, poly16x8x2_t val);      // ST1 {Vt.8H - Vt2.8H},[Xn]
void vst1_s64_x2(int64_t* ptr, int64x1x2_t val);         // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst1_u64_x2(uint64_t* ptr, uint64x1x2_t val);       // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst1_p64_x2(poly64_t* ptr, poly64x1x2_t val);       // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst1q_s64_x2(int64_t* ptr, int64x2x2_t val);        // ST1 {Vt.2D - Vt2.2D},[Xn]
void vst1q_u64_x2(uint64_t* ptr, uint64x2x2_t val);      // ST1 {Vt.2D - Vt2.2D},[Xn]
void vst1q_p64_x2(poly64_t* ptr, poly64x2x2_t val);      // ST1 {Vt.2D - Vt2.2D},[Xn]
void vst1_f64_x2(float64_t* ptr, float64x1x2_t val);     // ST1 {Vt.1D - Vt2.1D},[Xn]
void vst1q_f64_x2(float64_t* ptr, float64x2x2_t val);    // ST1 {Vt.2D - Vt2.2D},[Xn]
void vst1_s8_x3(int8_t* ptr, int8x8x3_t val);            // ST1 {Vt.8B - Vt3.8B},[Xn]
void vst1q_s8_x3(int8_t* ptr, int8x16x3_t val);          // ST1 {Vt.16B - Vt3.16B},[Xn]
void vst1_s16_x3(int16_t* ptr, int16x4x3_t val);         // ST1 {Vt.4H - Vt3.4H},[Xn]
void vst1q_s16_x3(int16_t* ptr, int16x8x3_t val);        // ST1 {Vt.8H - Vt3.8H},[Xn]
void vst1_s32_x3(int32_t* ptr, int32x2x3_t val);         // ST1 {Vt.2S - Vt3.2S},[Xn]
void vst1q_s32_x3(int32_t* ptr, int32x4x3_t val);        // ST1 {Vt.4S - Vt3.4S},[Xn]
void vst1_u8_x3(uint8_t* ptr, uint8x8x3_t val);          // ST1 {Vt.8B - Vt3.8B},[Xn]
void vst1q_u8_x3(uint8_t* ptr, uint8x16x3_t val);        // ST1 {Vt.16B - Vt3.16B},[Xn]
void vst1_u16_x3(uint16_t* ptr, uint16x4x3_t val);       // ST1 {Vt.4H - Vt3.4H},[Xn]
void vst1q_u16_x3(uint16_t* ptr, uint16x8x3_t val);      // ST1 {Vt.8H - Vt3.8H},[Xn]
void vst1_u32_x3(uint32_t* ptr, uint32x2x3_t val);       // ST1 {Vt.2S - Vt3.2S},[Xn]
void vst1q_u32_x3(uint32_t* ptr, uint32x4x3_t val);      // ST1 {Vt.4S - Vt3.4S},[Xn]
void vst1_f16_x3(float16_t* ptr, float16x4x3_t val);     // ST1 {Vt.4H - Vt3.4H},[Xn]
void vst1q_f16_x3(float16_t* ptr, float16x8x3_t val);    // ST1 {Vt.8H - Vt3.8H},[Xn]
void vst1_f32_x3(float32_t* ptr, float32x2x3_t val);     // ST1 {Vt.2S - Vt3.2S},[Xn]
void vst1q_f32_x3(float32_t* ptr, float32x4x3_t val);    // ST1 {Vt.4S - Vt3.4S},[Xn]
void vst1_p8_x3(poly8_t* ptr, poly8x8x3_t val);          // ST1 {Vt.8B - Vt3.8B},[Xn]
void vst1q_p8_x3(poly8_t* ptr, poly8x16x3_t val);        // ST1 {Vt.16B - Vt3.16B},[Xn]
void vst1_p16_x3(poly16_t* ptr, poly16x4x3_t val);       // ST1 {Vt.4H - Vt3.4H},[Xn]
void vst1q_p16_x3(poly16_t* ptr, poly16x8x3_t val);      // ST1 {Vt.8H - Vt3.8H},[Xn]
void vst1_s64_x3(int64_t* ptr, int64x1x3_t val);         // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst1_u64_x3(uint64_t* ptr, uint64x1x3_t val);       // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst1_p64_x3(poly64_t* ptr, poly64x1x3_t val);       // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst1q_s64_x3(int64_t* ptr, int64x2x3_t val);        // ST1 {Vt.2D - Vt3.2D},[Xn]
void vst1q_u64_x3(uint64_t* ptr, uint64x2x3_t val);      // ST1 {Vt.2D - Vt3.2D},[Xn]
void vst1q_p64_x3(poly64_t* ptr, poly64x2x3_t val);      // ST1 {Vt.2D - Vt3.2D},[Xn]
void vst1_f64_x3(float64_t* ptr, float64x1x3_t val);     // ST1 {Vt.1D - Vt3.1D},[Xn]
void vst1q_f64_x3(float64_t* ptr, float64x2x3_t val);    // ST1 {Vt.2D - Vt3.2D},[Xn]
void vst1_s8_x4(int8_t* ptr, int8x8x4_t val);            // ST1 {Vt.8B - Vt4.8B},[Xn]
void vst1q_s8_x4(int8_t* ptr, int8x16x4_t val);          // ST1 {Vt.16B - Vt4.16B},[Xn]
void vst1_s16_x4(int16_t* ptr, int16x4x4_t val);         // ST1 {Vt.4H - Vt4.4H},[Xn]
void vst1q_s16_x4(int16_t* ptr, int16x8x4_t val);        // ST1 {Vt.8H - Vt4.8H},[Xn]
void vst1_s32_x4(int32_t* ptr, int32x2x4_t val);         // ST1 {Vt.2S - Vt4.2S},[Xn]
void vst1q_s32_x4(int32_t* ptr, int32x4x4_t val);        // ST1 {Vt.4S - Vt4.4S},[Xn]
void vst1_u8_x4(uint8_t* ptr, uint8x8x4_t val);          // ST1 {Vt.8B - Vt4.8B},[Xn]
void vst1q_u8_x4(uint8_t* ptr, uint8x16x4_t val);        // ST1 {Vt.16B - Vt4.16B},[Xn]
void vst1_u16_x4(uint16_t* ptr, uint16x4x4_t val);       // ST1 {Vt.4H - Vt4.4H},[Xn]
void vst1q_u16_x4(uint16_t* ptr, uint16x8x4_t val);      // ST1 {Vt.8H - Vt4.8H},[Xn]
void vst1_u32_x4(uint32_t* ptr, uint32x2x4_t val);       // ST1 {Vt.2S - Vt4.2S},[Xn]
void vst1q_u32_x4(uint32_t* ptr, uint32x4x4_t val);      // ST1 {Vt.4S - Vt4.4S},[Xn]
void vst1_f16_x4(float16_t* ptr, float16x4x4_t val);     // ST1 {Vt.4H - Vt4.4H},[Xn]
void vst1q_f16_x4(float16_t* ptr, float16x8x4_t val);    // ST1 {Vt.8H - Vt4.8H},[Xn]
void vst1_f32_x4(float32_t* ptr, float32x2x4_t val);     // ST1 {Vt.2S - Vt4.2S},[Xn]
void vst1q_f32_x4(float32_t* ptr, float32x4x4_t val);    // ST1 {Vt.4S - Vt4.4S},[Xn]
void vst1_p8_x4(poly8_t* ptr, poly8x8x4_t val);          // ST1 {Vt.8B - Vt4.8B},[Xn]
void vst1q_p8_x4(poly8_t* ptr, poly8x16x4_t val);        // ST1 {Vt.16B - Vt4.16B},[Xn]
void vst1_p16_x4(poly16_t* ptr, poly16x4x4_t val);       // ST1 {Vt.4H - Vt4.4H},[Xn]
void vst1q_p16_x4(poly16_t* ptr, poly16x8x4_t val);      // ST1 {Vt.8H - Vt4.8H},[Xn]
void vst1_s64_x4(int64_t* ptr, int64x1x4_t val);         // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst1_u64_x4(uint64_t* ptr, uint64x1x4_t val);       // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst1_p64_x4(poly64_t* ptr, poly64x1x4_t val);       // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst1q_s64_x4(int64_t* ptr, int64x2x4_t val);        // ST1 {Vt.2D - Vt4.2D},[Xn]
void vst1q_u64_x4(uint64_t* ptr, uint64x2x4_t val);      // ST1 {Vt.2D - Vt4.2D},[Xn]
void vst1q_p64_x4(poly64_t* ptr, poly64x2x4_t val);      // ST1 {Vt.2D - Vt4.2D},[Xn]
void vst1_f64_x4(float64_t* ptr, float64x1x4_t val);     // ST1 {Vt.1D - Vt4.1D},[Xn]
void vst1q_f64_x4(float64_t* ptr, float64x2x4_t val);    // ST1 {Vt.2D - Vt4.2D},[Xn]
int8x8x2_t vld1_s8_x2(int8_t const* ptr);                // LD1 {Vt.8B - Vt2.8B},[Xn]
int8x16x2_t vld1q_s8_x2(int8_t const* ptr);              // LD1 {Vt.16B - Vt2.16B},[Xn]
int16x4x2_t vld1_s16_x2(int16_t const* ptr);             // LD1 {Vt.4H - Vt2.4H},[Xn]
int16x8x2_t vld1q_s16_x2(int16_t const* ptr);            // LD1 {Vt.8H - Vt2.8H},[Xn]
int32x2x2_t vld1_s32_x2(int32_t const* ptr);             // LD1 {Vt.2S - Vt2.2S},[Xn]
int32x4x2_t vld1q_s32_x2(int32_t const* ptr);            // LD1 {Vt.4S - Vt2.4S},[Xn]
uint8x8x2_t vld1_u8_x2(uint8_t const* ptr);              // LD1 {Vt.8B - Vt2.8B},[Xn]
uint8x16x2_t vld1q_u8_x2(uint8_t const* ptr);            // LD1 {Vt.16B - Vt2.16B},[Xn]
uint16x4x2_t vld1_u16_x2(uint16_t const* ptr);           // LD1 {Vt.4H - Vt2.4H},[Xn]
uint16x8x2_t vld1q_u16_x2(uint16_t const* ptr);          // LD1 {Vt.8H - Vt2.8H},[Xn]
uint32x2x2_t vld1_u32_x2(uint32_t const* ptr);           // LD1 {Vt.2S - Vt2.2S},[Xn]
uint32x4x2_t vld1q_u32_x2(uint32_t const* ptr);          // LD1 {Vt.4S - Vt2.4S},[Xn]
float16x4x2_t vld1_f16_x2(float16_t const* ptr);         // LD1 {Vt.4H - Vt2.4H},[Xn]
float16x8x2_t vld1q_f16_x2(float16_t const* ptr);        // LD1 {Vt.8H - Vt2.8H},[Xn]
float32x2x2_t vld1_f32_x2(float32_t const* ptr);         // LD1 {Vt.2S - Vt2.2S},[Xn]
float32x4x2_t vld1q_f32_x2(float32_t const* ptr);        // LD1 {Vt.4S - Vt2.4S},[Xn]
poly8x8x2_t vld1_p8_x2(poly8_t const* ptr);              // LD1 {Vt.8B - Vt2.8B},[Xn]
poly8x16x2_t vld1q_p8_x2(poly8_t const* ptr);            // LD1 {Vt.16B - Vt2.16B},[Xn]
poly16x4x2_t vld1_p16_x2(poly16_t const* ptr);           // LD1 {Vt.4H - Vt2.4H},[Xn]
poly16x8x2_t vld1q_p16_x2(poly16_t const* ptr);          // LD1 {Vt.8H - Vt2.8H},[Xn]
int64x1x2_t vld1_s64_x2(int64_t const* ptr);             // LD1 {Vt.1D - Vt2.1D},[Xn]
uint64x1x2_t vld1_u64_x2(uint64_t const* ptr);           // LD1 {Vt.1D - Vt2.1D},[Xn]
poly64x1x2_t vld1_p64_x2(poly64_t const* ptr);           // LD1 {Vt.1D - Vt2.1D},[Xn]
int64x2x2_t vld1q_s64_x2(int64_t const* ptr);            // LD1 {Vt.2D - Vt2.2D},[Xn]
uint64x2x2_t vld1q_u64_x2(uint64_t const* ptr);          // LD1 {Vt.2D - Vt2.2D},[Xn]
poly64x2x2_t vld1q_p64_x2(poly64_t const* ptr);          // LD1 {Vt.2D - Vt2.2D},[Xn]
float64x1x2_t vld1_f64_x2(float64_t const* ptr);         // LD1 {Vt.1D - Vt2.1D},[Xn]
float64x2x2_t vld1q_f64_x2(float64_t const* ptr);        // LD1 {Vt.2D - Vt2.2D},[Xn]
int8x8x3_t vld1_s8_x3(int8_t const* ptr);                // LD1 {Vt.8B - Vt3.8B},[Xn]
int8x16x3_t vld1q_s8_x3(int8_t const* ptr);              // LD1 {Vt.16B - Vt3.16B},[Xn]
int16x4x3_t vld1_s16_x3(int16_t const* ptr);             // LD1 {Vt.4H - Vt3.4H},[Xn]
int16x8x3_t vld1q_s16_x3(int16_t const* ptr);            // LD1 {Vt.8H - Vt3.8H},[Xn]
int32x2x3_t vld1_s32_x3(int32_t const* ptr);             // LD1 {Vt.2S - Vt3.2S},[Xn]
int32x4x3_t vld1q_s32_x3(int32_t const* ptr);            // LD1 {Vt.4S - Vt3.4S},[Xn]
uint8x8x3_t vld1_u8_x3(uint8_t const* ptr);              // LD1 {Vt.8B - Vt3.8B},[Xn]
uint8x16x3_t vld1q_u8_x3(uint8_t const* ptr);            // LD1 {Vt.16B - Vt3.16B},[Xn]
uint16x4x3_t vld1_u16_x3(uint16_t const* ptr);           // LD1 {Vt.4H - Vt3.4H},[Xn]
uint16x8x3_t vld1q_u16_x3(uint16_t const* ptr);          // LD1 {Vt.8H - Vt3.8H},[Xn]
uint32x2x3_t vld1_u32_x3(uint32_t const* ptr);           // LD1 {Vt.2S - Vt3.2S},[Xn]
uint32x4x3_t vld1q_u32_x3(uint32_t const* ptr);          // LD1 {Vt.4S - Vt3.4S},[Xn]
float16x4x3_t vld1_f16_x3(float16_t const* ptr);         // LD1 {Vt.4H - Vt3.4H},[Xn]
float16x8x3_t vld1q_f16_x3(float16_t const* ptr);        // LD1 {Vt.8H - Vt3.8H},[Xn]
float32x2x3_t vld1_f32_x3(float32_t const* ptr);         // LD1 {Vt.2S - Vt3.2S},[Xn]
float32x4x3_t vld1q_f32_x3(float32_t const* ptr);        // LD1 {Vt.4S - Vt3.4S},[Xn]
poly8x8x3_t vld1_p8_x3(poly8_t const* ptr);              // LD1 {Vt.8B - Vt3.8B},[Xn]
poly8x16x3_t vld1q_p8_x3(poly8_t const* ptr);            // LD1 {Vt.16B - Vt3.16B},[Xn]
poly16x4x3_t vld1_p16_x3(poly16_t const* ptr);           // LD1 {Vt.4H - Vt3.4H},[Xn]
poly16x8x3_t vld1q_p16_x3(poly16_t const* ptr);          // LD1 {Vt.8H - Vt3.8H},[Xn]
int64x1x3_t vld1_s64_x3(int64_t const* ptr);             // LD1 {Vt.1D - Vt3.1D},[Xn]
uint64x1x3_t vld1_u64_x3(uint64_t const* ptr);           // LD1 {Vt.1D - Vt3.1D},[Xn]
poly64x1x3_t vld1_p64_x3(poly64_t const* ptr);           // LD1 {Vt.1D - Vt3.1D},[Xn]
int64x2x3_t vld1q_s64_x3(int64_t const* ptr);            // LD1 {Vt.2D - Vt3.2D},[Xn]
uint64x2x3_t vld1q_u64_x3(uint64_t const* ptr);          // LD1 {Vt.2D - Vt3.2D},[Xn]
poly64x2x3_t vld1q_p64_x3(poly64_t const* ptr);          // LD1 {Vt.2D - Vt3.2D},[Xn]
float64x1x3_t vld1_f64_x3(float64_t const* ptr);         // LD1 {Vt.1D - Vt3.1D},[Xn]
float64x2x3_t vld1q_f64_x3(float64_t const* ptr);        // LD1 {Vt.2D - Vt3.2D},[Xn]
int8x8x4_t vld1_s8_x4(int8_t const* ptr);                // LD1 {Vt.8B - Vt4.8B},[Xn]
int8x16x4_t vld1q_s8_x4(int8_t const* ptr);              // LD1 {Vt.16B - Vt4.16B},[Xn]
int16x4x4_t vld1_s16_x4(int16_t const* ptr);             // LD1 {Vt.4H - Vt4.4H},[Xn]
int16x8x4_t vld1q_s16_x4(int16_t const* ptr);            // LD1 {Vt.8H - Vt4.8H},[Xn]
int32x2x4_t vld1_s32_x4(int32_t const* ptr);             // LD1 {Vt.2S - Vt4.2S},[Xn]
int32x4x4_t vld1q_s32_x4(int32_t const* ptr);            // LD1 {Vt.4S - Vt4.4S},[Xn]
uint8x8x4_t vld1_u8_x4(uint8_t const* ptr);              // LD1 {Vt.8B - Vt4.8B},[Xn]
uint8x16x4_t vld1q_u8_x4(uint8_t const* ptr);            // LD1 {Vt.16B - Vt4.16B},[Xn]
uint16x4x4_t vld1_u16_x4(uint16_t const* ptr);           // LD1 {Vt.4H - Vt4.4H},[Xn]
uint16x8x4_t vld1q_u16_x4(uint16_t const* ptr);          // LD1 {Vt.8H - Vt4.8H},[Xn]
uint32x2x4_t vld1_u32_x4(uint32_t const* ptr);           // LD1 {Vt.2S - Vt4.2S},[Xn]
uint32x4x4_t vld1q_u32_x4(uint32_t const* ptr);          // LD1 {Vt.4S - Vt4.4S},[Xn]
float16x4x4_t vld1_f16_x4(float16_t const* ptr);         // LD1 {Vt.4H - Vt4.4H},[Xn]
float16x8x4_t vld1q_f16_x4(float16_t const* ptr);        // LD1 {Vt.8H - Vt4.8H},[Xn]
float32x2x4_t vld1_f32_x4(float32_t const* ptr);         // LD1 {Vt.2S - Vt4.2S},[Xn]
float32x4x4_t vld1q_f32_x4(float32_t const* ptr);        // LD1 {Vt.4S - Vt4.4S},[Xn]
poly8x8x4_t vld1_p8_x4(poly8_t const* ptr);              // LD1 {Vt.8B - Vt4.8B},[Xn]
poly8x16x4_t vld1q_p8_x4(poly8_t const* ptr);            // LD1 {Vt.16B - Vt4.16B},[Xn]
poly16x4x4_t vld1_p16_x4(poly16_t const* ptr);           // LD1 {Vt.4H - Vt4.4H},[Xn]
poly16x8x4_t vld1q_p16_x4(poly16_t const* ptr);          // LD1 {Vt.8H - Vt4.8H},[Xn]
int64x1x4_t vld1_s64_x4(int64_t const* ptr);             // LD1 {Vt.1D - Vt4.1D},[Xn]
uint64x1x4_t vld1_u64_x4(uint64_t const* ptr);           // LD1 {Vt.1D - Vt4.1D},[Xn]
poly64x1x4_t vld1_p64_x4(poly64_t const* ptr);           // LD1 {Vt.1D - Vt4.1D},[Xn]
int64x2x4_t vld1q_s64_x4(int64_t const* ptr);            // LD1 {Vt.2D - Vt4.2D},[Xn]
uint64x2x4_t vld1q_u64_x4(uint64_t const* ptr);          // LD1 {Vt.2D - Vt4.2D},[Xn]
poly64x2x4_t vld1q_p64_x4(poly64_t const* ptr);          // LD1 {Vt.2D - Vt4.2D},[Xn]
float64x1x4_t vld1_f64_x4(float64_t const* ptr);         // LD1 {Vt.1D - Vt4.1D},[Xn]
float64x2x4_t vld1q_f64_x4(float64_t const* ptr);        // LD1 {Vt.2D - Vt4.2D},[Xn]
int8x8_t vpadd_s8(int8x8_t a, int8x8_t b);               // ADDP Vd.8B,Vn.8B,Vm.8B
int16x4_t vpadd_s16(int16x4_t a, int16x4_t b);           // ADDP Vd.4H,Vn.4H,Vm.4H
int32x2_t vpadd_s32(int32x2_t a, int32x2_t b);           // ADDP Vd.2S,Vn.2S,Vm.2S
uint8x8_t vpadd_u8(uint8x8_t a, uint8x8_t b);            // ADDP Vd.8B,Vn.8B,Vm.8B
uint16x4_t vpadd_u16(uint16x4_t a, uint16x4_t b);        // ADDP Vd.4H,Vn.4H,Vm.4H
uint32x2_t vpadd_u32(uint32x2_t a, uint32x2_t b);        // ADDP Vd.2S,Vn.2S,Vm.2S
float32x2_t vpadd_f32(float32x2_t a, float32x2_t b);     // FADDP Vd.2S,Vn.2S,Vm.2S
int8x16_t vpaddq_s8(int8x16_t a, int8x16_t b);           // ADDP Vd.16B,Vn.16B,Vm.16B
int16x8_t vpaddq_s16(int16x8_t a, int16x8_t b);          // ADDP Vd.8H,Vn.8H,Vm.8H
int32x4_t vpaddq_s32(int32x4_t a, int32x4_t b);          // ADDP Vd.4S,Vn.4S,Vm.4S
int64x2_t vpaddq_s64(int64x2_t a, int64x2_t b);          // ADDP Vd.2D,Vn.2D,Vm.2D
uint8x16_t vpaddq_u8(uint8x16_t a, uint8x16_t b);        // ADDP Vd.16B,Vn.16B,Vm.16B
uint16x8_t vpaddq_u16(uint16x8_t a, uint16x8_t b);       // ADDP Vd.8H,Vn.8H,Vm.8H
uint32x4_t vpaddq_u32(uint32x4_t a, uint32x4_t b);       // ADDP Vd.4S,Vn.4S,Vm.4S
uint64x2_t vpaddq_u64(uint64x2_t a, uint64x2_t b);       // ADDP Vd.2D,Vn.2D,Vm.2D
float32x4_t vpaddq_f32(float32x4_t a, float32x4_t b);    // FADDP Vd.4S,Vn.4S,Vm.4S
float64x2_t vpaddq_f64(float64x2_t a, float64x2_t b);    // FADDP Vd.2D,Vn.2D,Vm.2D
int16x4_t vpaddl_s8(int8x8_t a);                         // SADDLP Vd.4H,Vn.8B
int16x8_t vpaddlq_s8(int8x16_t a);                       // SADDLP Vd.8H,Vn.16B
int32x2_t vpaddl_s16(int16x4_t a);                       // SADDLP Vd.2S,Vn.4H
int32x4_t vpaddlq_s16(int16x8_t a);                      // SADDLP Vd.4S,Vn.8H
int64x1_t vpaddl_s32(int32x2_t a);                       // SADDLP Vd.1D,Vn.2S
int64x2_t vpaddlq_s32(int32x4_t a);                      // SADDLP Vd.2D,Vn.4S
uint16x4_t vpaddl_u8(uint8x8_t a);                       // UADDLP Vd.4H,Vn.8B
uint16x8_t vpaddlq_u8(uint8x16_t a);                     // UADDLP Vd.8H,Vn.16B
uint32x2_t vpaddl_u16(uint16x4_t a);                     // UADDLP Vd.2S,Vn.4H
uint32x4_t vpaddlq_u16(uint16x8_t a);                    // UADDLP Vd.4S,Vn.8H
uint64x1_t vpaddl_u32(uint32x2_t a);                     // UADDLP Vd.1D,Vn.2S
uint64x2_t vpaddlq_u32(uint32x4_t a);                    // UADDLP Vd.2D,Vn.4S
int16x4_t vpadal_s8(int16x4_t a, int8x8_t b);            // SADALP Vd.4H,Vn.8B
int16x8_t vpadalq_s8(int16x8_t a, int8x16_t b);          // SADALP Vd.8H,Vn.16B
int32x2_t vpadal_s16(int32x2_t a, int16x4_t b);          // SADALP Vd.2S,Vn.4H
int32x4_t vpadalq_s16(int32x4_t a, int16x8_t b);         // SADALP Vd.4S,Vn.8H
int64x1_t vpadal_s32(int64x1_t a, int32x2_t b);          // SADALP Vd.1D,Vn.2S
int64x2_t vpadalq_s32(int64x2_t a, int32x4_t b);         // SADALP Vd.2D,Vn.4S
uint16x4_t vpadal_u8(uint16x4_t a, uint8x8_t b);         // UADALP Vd.4H,Vn.8B
uint16x8_t vpadalq_u8(uint16x8_t a, uint8x16_t b);       // UADALP Vd.8H,Vn.16B
uint32x2_t vpadal_u16(uint32x2_t a, uint16x4_t b);       // UADALP Vd.2S,Vn.4H
uint32x4_t vpadalq_u16(uint32x4_t a, uint16x8_t b);      // UADALP Vd.4S,Vn.8H
uint64x1_t vpadal_u32(uint64x1_t a, uint32x2_t b);       // UADALP Vd.1D,Vn.2S
uint64x2_t vpadalq_u32(uint64x2_t a, uint32x4_t b);      // UADALP Vd.2D,Vn.4S
int8x8_t vpmax_s8(int8x8_t a, int8x8_t b);               // SMAXP Vd.8B,Vn.8B,Vm.8B
int16x4_t vpmax_s16(int16x4_t a, int16x4_t b);           // SMAXP Vd.4H,Vn.4H,Vm.4H
int32x2_t vpmax_s32(int32x2_t a, int32x2_t b);           // SMAXP Vd.2S,Vn.2S,Vm.2S
uint8x8_t vpmax_u8(uint8x8_t a, uint8x8_t b);            // UMAXP Vd.8B,Vn.8B,Vm.8B
uint16x4_t vpmax_u16(uint16x4_t a, uint16x4_t b);        // UMAXP Vd.4H,Vn.4H,Vm.4H
uint32x2_t vpmax_u32(uint32x2_t a, uint32x2_t b);        // UMAXP Vd.2S,Vn.2S,Vm.2S
float32x2_t vpmax_f32(float32x2_t a, float32x2_t b);     // FMAXP Vd.2S,Vn.2S,Vm.2S
int8x16_t vpmaxq_s8(int8x16_t a, int8x16_t b);           // SMAXP Vd.16B,Vn.16B,Vm.16B
int16x8_t vpmaxq_s16(int16x8_t a, int16x8_t b);          // SMAXP Vd.8H,Vn.8H,Vm.8H
int32x4_t vpmaxq_s32(int32x4_t a, int32x4_t b);          // SMAXP Vd.4S,Vn.4S,Vm.4S
uint8x16_t vpmaxq_u8(uint8x16_t a, uint8x16_t b);        // UMAXP Vd.16B,Vn.16B,Vm.16B
uint16x8_t vpmaxq_u16(uint16x8_t a, uint16x8_t b);       // UMAXP Vd.8H,Vn.8H,Vm.8H
uint32x4_t vpmaxq_u32(uint32x4_t a, uint32x4_t b);       // UMAXP Vd.4S,Vn.4S,Vm.4S
float32x4_t vpmaxq_f32(float32x4_t a, float32x4_t b);    // FMAXP Vd.4S,Vn.4S,Vm.4S
float64x2_t vpmaxq_f64(float64x2_t a, float64x2_t b);    // FMAXP Vd.2D,Vn.2D,Vm.2D
int8x8_t vpmin_s8(int8x8_t a, int8x8_t b);               // SMINP Vd.8B,Vn.8B,Vm.8B
int16x4_t vpmin_s16(int16x4_t a, int16x4_t b);           // SMINP Vd.4H,Vn.4H,Vm.4H
int32x2_t vpmin_s32(int32x2_t a, int32x2_t b);           // SMINP Vd.2S,Vn.2S,Vm.2S
uint8x8_t vpmin_u8(uint8x8_t a, uint8x8_t b);            // UMINP Vd.8B,Vn.8B,Vm.8B
uint16x4_t vpmin_u16(uint16x4_t a, uint16x4_t b);        // UMINP Vd.4H,Vn.4H,Vm.4H
uint32x2_t vpmin_u32(uint32x2_t a, uint32x2_t b);        // UMINP Vd.2S,Vn.2S,Vm.2S
float32x2_t vpmin_f32(float32x2_t a, float32x2_t b);     // FMINP Vd.2S,Vn.2S,Vm.2S
int8x16_t vpminq_s8(int8x16_t a, int8x16_t b);           // SMINP Vd.16B,Vn.16B,Vm.16B
int16x8_t vpminq_s16(int16x8_t a, int16x8_t b);          // SMINP Vd.8H,Vn.8H,Vm.8H
int32x4_t vpminq_s32(int32x4_t a, int32x4_t b);          // SMINP Vd.4S,Vn.4S,Vm.4S
uint8x16_t vpminq_u8(uint8x16_t a, uint8x16_t b);        // UMINP Vd.16B,Vn.16B,Vm.16B
uint16x8_t vpminq_u16(uint16x8_t a, uint16x8_t b);       // UMINP Vd.8H,Vn.8H,Vm.8H
uint32x4_t vpminq_u32(uint32x4_t a, uint32x4_t b);       // UMINP Vd.4S,Vn.4S,Vm.4S
float32x4_t vpminq_f32(float32x4_t a, float32x4_t b);    // FMINP Vd.4S,Vn.4S,Vm.4S
float64x2_t vpminq_f64(float64x2_t a, float64x2_t b);    // FMINP Vd.2D,Vn.2D,Vm.2D
float32x2_t vpmaxnm_f32(float32x2_t a, float32x2_t b);   // FMAXNMP Vd.2S,Vn.2S,Vm.2S
float32x4_t vpmaxnmq_f32(float32x4_t a, float32x4_t b);  // FMAXNMP Vd.4S,Vn.4S,Vm.4S
float64x2_t vpmaxnmq_f64(float64x2_t a, float64x2_t b);  // FMAXNMP Vd.2D,Vn.2D,Vm.2D
float32x2_t vpminnm_f32(float32x2_t a, float32x2_t b);   // FMINNMP Vd.2S,Vn.2S,Vm.2S
float32x4_t vpminnmq_f32(float32x4_t a, float32x4_t b);  // FMINNMP Vd.4S,Vn.4S,Vm.4S
float64x2_t vpminnmq_f64(float64x2_t a, float64x2_t b);  // FMINNMP Vd.2D,Vn.2D,Vm.2D
int64_t vpaddd_s64(int64x2_t a);                         // ADDP Dd,Vn.2D
uint64_t vpaddd_u64(uint64x2_t a);                       // ADDP Dd,Vn.2D
float32_t vpadds_f32(float32x2_t a);                     // FADDP Sd,Vn.2S
float64_t vpaddd_f64(float64x2_t a);                     // FADDP Dd,Vn.2D
float32_t vpmaxs_f32(float32x2_t a);                     // FMAXP Sd,Vn.2S
float64_t vpmaxqd_f64(float64x2_t a);                    // FMAXP Dd,Vn.2D
float32_t vpmins_f32(float32x2_t a);                     // FMINP Sd,Vn.2S
float64_t vpminqd_f64(float64x2_t a);                    // FMINP Dd,Vn.2D
float32_t vpmaxnms_f32(float32x2_t a);                   // FMAXNMP Sd,Vn.2S
float64_t vpmaxnmqd_f64(float64x2_t a);                  // FMAXNMP Dd,Vn.2D
float32_t vpminnms_f32(float32x2_t a);                   // FMINNMP Sd,Vn.2S
float64_t vpminnmqd_f64(float64x2_t a);                  // FMINNMP Dd,Vn.2D
int8_t vaddv_s8(int8x8_t a);                             // ADDV Bd,Vn.8B
int8_t vaddvq_s8(int8x16_t a);                           // ADDV Bd,Vn.16B
int16_t vaddv_s16(int16x4_t a);                          // ADDV Hd,Vn.4H
int16_t vaddvq_s16(int16x8_t a);                         // ADDV Hd,Vn.8H
int32_t vaddv_s32(int32x2_t a);                          // ADDP Vd.2S,Vn.2S,Vm.2S
int32_t vaddvq_s32(int32x4_t a);                         // ADDV Sd,Vn.4S
int64_t vaddvq_s64(int64x2_t a);                         // ADDP Dd,Vn.2D
uint8_t vaddv_u8(uint8x8_t a);                           // ADDV Bd,Vn.8B
uint8_t vaddvq_u8(uint8x16_t a);                         // ADDV Bd,Vn.16B
uint16_t vaddv_u16(uint16x4_t a);                        // ADDV Hd,Vn.4H
uint16_t vaddvq_u16(uint16x8_t a);                       // ADDV Hd,Vn.8H
uint32_t vaddv_u32(uint32x2_t a);                        // ADDP Vd.2S,Vn.2S,Vm.2S
uint32_t vaddvq_u32(uint32x4_t a);                       // ADDV Sd,Vn.4S
uint64_t vaddvq_u64(uint64x2_t a);                       // ADDP Dd,Vn.2D
float32_t vaddv_f32(float32x2_t a);                      // FADDP Sd,Vn.2S
float32_t vaddvq_f32(float32x4_t a);                     // FADDP Vt.4S,Vn.4S,Vm.4S; FADDP Sd,Vt.2S
float64_t vaddvq_f64(float64x2_t a);                     // FADDP Dd,Vn.2D
int16_t vaddlv_s8(int8x8_t a);                           // SADDLV Hd,Vn.8B
int16_t vaddlvq_s8(int8x16_t a);                         // SADDLV Hd,Vn.16B
int32_t vaddlv_s16(int16x4_t a);                         // SADDLV Sd,Vn.4H
int32_t vaddlvq_s16(int16x8_t a);                        // SADDLV Sd,Vn.8H
int64_t vaddlv_s32(int32x2_t a);                         // SADDLP Vd.1D,Vn.2S
int64_t vaddlvq_s32(int32x4_t a);                        // SADDLV Dd,Vn.4S
uint16_t vaddlv_u8(uint8x8_t a);                         // UADDLV Hd,Vn.8B
uint16_t vaddlvq_u8(uint8x16_t a);                       // UADDLV Hd,Vn.16B
uint32_t vaddlv_u16(uint16x4_t a);                       // UADDLV Sd,Vn.4H
uint32_t vaddlvq_u16(uint16x8_t a);                      // UADDLV Sd,Vn.8H
uint64_t vaddlv_u32(uint32x2_t a);                       // UADDLP Vd.1D,Vn.2S
uint64_t vaddlvq_u32(uint32x4_t a);                      // UADDLV Dd,Vn.4S
int8_t vmaxv_s8(int8x8_t a);                             // SMAXV Bd,Vn.8B
int8_t vmaxvq_s8(int8x16_t a);                           // SMAXV Bd,Vn.16B
int16_t vmaxv_s16(int16x4_t a);                          // SMAXV Hd,Vn.4H
int16_t vmaxvq_s16(int16x8_t a);                         // SMAXV Hd,Vn.8H
int32_t vmaxv_s32(int32x2_t a);                          // SMAXP Vd.2S,Vn.2S,Vm.2S
int32_t vmaxvq_s32(int32x4_t a);                         // SMAXV Sd,Vn.4S
uint8_t vmaxv_u8(uint8x8_t a);                           // UMAXV Bd,Vn.8B
uint8_t vmaxvq_u8(uint8x16_t a);                         // UMAXV Bd,Vn.16B
uint16_t vmaxv_u16(uint16x4_t a);                        // UMAXV Hd,Vn.4H
uint16_t vmaxvq_u16(uint16x8_t a);                       // UMAXV Hd,Vn.8H
uint32_t vmaxv_u32(uint32x2_t a);                        // UMAXP Vd.2S,Vn.2S,Vm.2S
uint32_t vmaxvq_u32(uint32x4_t a);                       // UMAXV Sd,Vn.4S
float32_t vmaxv_f32(float32x2_t a);                      // FMAXP Sd,Vn.2S
float32_t vmaxvq_f32(float32x4_t a);                     // FMAXV Sd,Vn.4S
float64_t vmaxvq_f64(float64x2_t a);                     // FMAXP Dd,Vn.2D
int8_t vminv_s8(int8x8_t a);                             // SMINV Bd,Vn.8B
int8_t vminvq_s8(int8x16_t a);                           // SMINV Bd,Vn.16B
int16_t vminv_s16(int16x4_t a);                          // SMINV Hd,Vn.4H
int16_t vminvq_s16(int16x8_t a);                         // SMINV Hd,Vn.8H
int32_t vminv_s32(int32x2_t a);                          // SMINP Vd.2S,Vn.2S,Vm.2S
int32_t vminvq_s32(int32x4_t a);                         // SMINV Sd,Vn.4S
uint8_t vminv_u8(uint8x8_t a);                           // UMINV Bd,Vn.8B
uint8_t vminvq_u8(uint8x16_t a);                         // UMINV Bd,Vn.16B
uint16_t vminv_u16(uint16x4_t a);                        // UMINV Hd,Vn.4H
uint16_t vminvq_u16(uint16x8_t a);                       // UMINV Hd,Vn.8H
uint32_t vminv_u32(uint32x2_t a);                        // UMINP Vd.2S,Vn.2S,Vm.2S
uint32_t vminvq_u32(uint32x4_t a);                       // UMINV Sd,Vn.4S
float32_t vminv_f32(float32x2_t a);                      // FMINP Sd,Vn.2S
float32_t vminvq_f32(float32x4_t a);                     // FMINV Sd,Vn.4S
float64_t vminvq_f64(float64x2_t a);                     // FMINP Dd,Vn.2D
float32_t vmaxnmv_f32(float32x2_t a);                    // FMAXNMP Sd,Vn.2S
float32_t vmaxnmvq_f32(float32x4_t a);                   // FMAXNMV Sd,Vn.4S
float64_t vmaxnmvq_f64(float64x2_t a);                   // FMAXNMP Dd,Vn.2D
float32_t vminnmv_f32(float32x2_t a);                    // FMINNMP Sd,Vn.2S
float32_t vminnmvq_f32(float32x4_t a);                   // FMINNMV Sd,Vn.4S
float64_t vminnmvq_f64(float64x2_t a);                   // FMINNMP Dd,Vn.2D
int8x8_t vext_s8(int8x8_t a, int8x8_t b, const int n);   // EXT Vd.8B,Vn.8B,Vm.8B,#n
int8x16_t vextq_s8(int8x16_t a, int8x16_t b, const int n);      // EXT Vd.16B,Vn.16B,Vm.16B,#n
int16x4_t vext_s16(int16x4_t a, int16x4_t b, const int n);      // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<1)
int16x8_t vextq_s16(int16x8_t a, int16x8_t b, const int n);     // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<1)
int32x2_t vext_s32(int32x2_t a, int32x2_t b, const int n);      // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<2)
int32x4_t vextq_s32(int32x4_t a, int32x4_t b, const int n);     // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<2)
int64x1_t vext_s64(int64x1_t a, int64x1_t b, const int n);      // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<3)
int64x2_t vextq_s64(int64x2_t a, int64x2_t b, const int n);     // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<3)
uint8x8_t vext_u8(uint8x8_t a, uint8x8_t b, const int n);       // EXT Vd.8B,Vn.8B,Vm.8B,#n
uint8x16_t vextq_u8(uint8x16_t a, uint8x16_t b, const int n);   // EXT Vd.16B,Vn.16B,Vm.16B,#n
uint16x4_t vext_u16(uint16x4_t a, uint16x4_t b, const int n);   // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<1)
uint16x8_t vextq_u16(uint16x8_t a, uint16x8_t b, const int n);  // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<1)
uint32x2_t vext_u32(uint32x2_t a, uint32x2_t b, const int n);   // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<2)
uint32x4_t vextq_u32(uint32x4_t a, uint32x4_t b, const int n);  // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<2)
uint64x1_t vext_u64(uint64x1_t a, uint64x1_t b, const int n);   // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<3)
uint64x2_t vextq_u64(uint64x2_t a, uint64x2_t b, const int n);  // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<3)
poly64x1_t vext_p64(poly64x1_t a, poly64x1_t b, const int n);   // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<3)
poly64x2_t vextq_p64(poly64x2_t a, poly64x2_t b, const int n);  // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<3)
float32x2_t vext_f32(float32x2_t a, float32x2_t b, const int n);  // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<2)
float32x4_t vextq_f32(
    float32x4_t a, float32x4_t b, const int n);  // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<2)
float64x1_t vext_f64(float64x1_t a, float64x1_t b, const int n);  // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<3)
float64x2_t vextq_f64(
    float64x2_t a, float64x2_t b, const int n);                 // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<3)
poly8x8_t vext_p8(poly8x8_t a, poly8x8_t b, const int n);       // EXT Vd.8B,Vn.8B,Vm.8B,#n
poly8x16_t vextq_p8(poly8x16_t a, poly8x16_t b, const int n);   // EXT Vd.16B,Vn.16B,Vm.16B,#n
poly16x4_t vext_p16(poly16x4_t a, poly16x4_t b, const int n);   // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<1)
poly16x8_t vextq_p16(poly16x8_t a, poly16x8_t b, const int n);  // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<1)
int8x8_t vrev64_s8(int8x8_t vec);                               // REV64 Vd.8B,Vn.8B
int8x16_t vrev64q_s8(int8x16_t vec);                            // REV64 Vd.16B,Vn.16B
int16x4_t vrev64_s16(int16x4_t vec);                            // REV64 Vd.4H,Vn.4H
int16x8_t vrev64q_s16(int16x8_t vec);                           // REV64 Vd.8H,Vn.8H
int32x2_t vrev64_s32(int32x2_t vec);                            // REV64 Vd.2S,Vn.2S
int32x4_t vrev64q_s32(int32x4_t vec);                           // REV64 Vd.4S,Vn.4S
uint8x8_t vrev64_u8(uint8x8_t vec);                             // REV64 Vd.8B,Vn.8B
uint8x16_t vrev64q_u8(uint8x16_t vec);                          // REV64 Vd.16B,Vn.16B
uint16x4_t vrev64_u16(uint16x4_t vec);                          // REV64 Vd.4H,Vn.4H
uint16x8_t vrev64q_u16(uint16x8_t vec);                         // REV64 Vd.8H,Vn.8H
uint32x2_t vrev64_u32(uint32x2_t vec);                          // REV64 Vd.2S,Vn.2S
uint32x4_t vrev64q_u32(uint32x4_t vec);                         // REV64 Vd.4S,Vn.4S
float32x2_t vrev64_f32(float32x2_t vec);                        // REV64 Vd.2S,Vn.2S
float32x4_t vrev64q_f32(float32x4_t vec);                       // REV64 Vd.4S,Vn.4S
poly8x8_t vrev64_p8(poly8x8_t vec);                             // REV64 Vd.8B,Vn.8B
poly8x16_t vrev64q_p8(poly8x16_t vec);                          // REV64 Vd.16B,Vn.16B
poly16x4_t vrev64_p16(poly16x4_t vec);                          // REV64 Vd.4H,Vn.4H
poly16x8_t vrev64q_p16(poly16x8_t vec);                         // REV64 Vd.8H,Vn.8H
int8x8_t vrev32_s8(int8x8_t vec);                               // REV32 Vd.8B,Vn.8B
int8x16_t vrev32q_s8(int8x16_t vec);                            // REV32 Vd.16B,Vn.16B
int16x4_t vrev32_s16(int16x4_t vec);                            // REV32 Vd.4H,Vn.4H
int16x8_t vrev32q_s16(int16x8_t vec);                           // REV32 Vd.8H,Vn.8H
uint8x8_t vrev32_u8(uint8x8_t vec);                             // REV32 Vd.8B,Vn.8B
uint8x16_t vrev32q_u8(uint8x16_t vec);                          // REV32 Vd.16B,Vn.16B
uint16x4_t vrev32_u16(uint16x4_t vec);                          // REV32 Vd.4H,Vn.4H
uint16x8_t vrev32q_u16(uint16x8_t vec);                         // REV32 Vd.8H,Vn.8H
poly8x8_t vrev32_p8(poly8x8_t vec);                             // REV32 Vd.8B,Vn.8B
poly8x16_t vrev32q_p8(poly8x16_t vec);                          // REV32 Vd.16B,Vn.16B
poly16x4_t vrev32_p16(poly16x4_t vec);                          // REV32 Vd.4H,Vn.4H
poly16x8_t vrev32q_p16(poly16x8_t vec);                         // REV32 Vd.8H,Vn.8H
int8x8_t vrev16_s8(int8x8_t vec);                               // REV16 Vd.8B,Vn.8B
int8x16_t vrev16q_s8(int8x16_t vec);                            // REV16 Vd.16B,Vn.16B
uint8x8_t vrev16_u8(uint8x8_t vec);                             // REV16 Vd.8B,Vn.8B
uint8x16_t vrev16q_u8(uint8x16_t vec);                          // REV16 Vd.16B,Vn.16B
poly8x8_t vrev16_p8(poly8x8_t vec);                             // REV16 Vd.8B,Vn.8B
poly8x16_t vrev16q_p8(poly8x16_t vec);                          // REV16 Vd.16B,Vn.16B
int8x8_t vzip1_s8(int8x8_t a, int8x8_t b);                      // ZIP1 Vd.8B,Vn.8B,Vm.8B
int8x16_t vzip1q_s8(int8x16_t a, int8x16_t b);                  // ZIP1 Vd.16B,Vn.16B,Vm.16B
int16x4_t vzip1_s16(int16x4_t a, int16x4_t b);                  // ZIP1 Vd.4H,Vn.4H,Vm.4H
int16x8_t vzip1q_s16(int16x8_t a, int16x8_t b);                 // ZIP1 Vd.8H,Vn.8H,Vm.8H
int32x2_t vzip1_s32(int32x2_t a, int32x2_t b);                  // ZIP1 Vd.2S,Vn.2S,Vm.2S
int32x4_t vzip1q_s32(int32x4_t a, int32x4_t b);                 // ZIP1 Vd.4S,Vn.4S,Vm.4S
int64x2_t vzip1q_s64(int64x2_t a, int64x2_t b);                 // ZIP1 Vd.2D,Vn.2D,Vm.2D
uint8x8_t vzip1_u8(uint8x8_t a, uint8x8_t b);                   // ZIP1 Vd.8B,Vn.8B,Vm.8B
uint8x16_t vzip1q_u8(uint8x16_t a, uint8x16_t b);               // ZIP1 Vd.16B,Vn.16B,Vm.16B
uint16x4_t vzip1_u16(uint16x4_t a, uint16x4_t b);               // ZIP1 Vd.4H,Vn.4H,Vm.4H
uint16x8_t vzip1q_u16(uint16x8_t a, uint16x8_t b);              // ZIP1 Vd.8H,Vn.8H,Vm.8H
uint32x2_t vzip1_u32(uint32x2_t a, uint32x2_t b);               // ZIP1 Vd.2S,Vn.2S,Vm.2S
uint32x4_t vzip1q_u32(uint32x4_t a, uint32x4_t b);              // ZIP1 Vd.4S,Vn.4S,Vm.4S
uint64x2_t vzip1q_u64(uint64x2_t a, uint64x2_t b);              // ZIP1 Vd.2D,Vn.2D,Vm.2D
poly64x2_t vzip1q_p64(poly64x2_t a, poly64x2_t b);              // ZIP1 Vd.2D,Vn.2D,Vm.2D
float32x2_t vzip1_f32(float32x2_t a, float32x2_t b);            // ZIP1 Vd.2S,Vn.2S,Vm.2S
float32x4_t vzip1q_f32(float32x4_t a, float32x4_t b);           // ZIP1 Vd.4S,Vn.4S,Vm.4S
float64x2_t vzip1q_f64(float64x2_t a, float64x2_t b);           // ZIP1 Vd.2D,Vn.2D,Vm.2D
poly8x8_t vzip1_p8(poly8x8_t a, poly8x8_t b);                   // ZIP1 Vd.8B,Vn.8B,Vm.8B
poly8x16_t vzip1q_p8(poly8x16_t a, poly8x16_t b);               // ZIP1 Vd.16B,Vn.16B,Vm.16B
poly16x4_t vzip1_p16(poly16x4_t a, poly16x4_t b);               // ZIP1 Vd.4H,Vn.4H,Vm.4H
poly16x8_t vzip1q_p16(poly16x8_t a, poly16x8_t b);              // ZIP1 Vd.8H,Vn.8H,Vm.8H
int8x8_t vzip2_s8(int8x8_t a, int8x8_t b);                      // ZIP2 Vd.8B,Vn.8B,Vm.8B
int8x16_t vzip2q_s8(int8x16_t a, int8x16_t b);                  // ZIP2 Vd.16B,Vn.16B,Vm.16B
int16x4_t vzip2_s16(int16x4_t a, int16x4_t b);                  // ZIP2 Vd.4H,Vn.4H,Vm.4H
int16x8_t vzip2q_s16(int16x8_t a, int16x8_t b);                 // ZIP2 Vd.8H,Vn.8H,Vm.8H
int32x2_t vzip2_s32(int32x2_t a, int32x2_t b);                  // ZIP2 Vd.2S,Vn.2S,Vm.2S
int32x4_t vzip2q_s32(int32x4_t a, int32x4_t b);                 // ZIP2 Vd.4S,Vn.4S,Vm.4S
int64x2_t vzip2q_s64(int64x2_t a, int64x2_t b);                 // ZIP2 Vd.2D,Vn.2D,Vm.2D
uint8x8_t vzip2_u8(uint8x8_t a, uint8x8_t b);                   // ZIP2 Vd.8B,Vn.8B,Vm.8B
uint8x16_t vzip2q_u8(uint8x16_t a, uint8x16_t b);               // ZIP2 Vd.16B,Vn.16B,Vm.16B
uint16x4_t vzip2_u16(uint16x4_t a, uint16x4_t b);               // ZIP2 Vd.4H,Vn.4H,Vm.4H
uint16x8_t vzip2q_u16(uint16x8_t a, uint16x8_t b);              // ZIP2 Vd.8H,Vn.8H,Vm.8H
uint32x2_t vzip2_u32(uint32x2_t a, uint32x2_t b);               // ZIP2 Vd.2S,Vn.2S,Vm.2S
uint32x4_t vzip2q_u32(uint32x4_t a, uint32x4_t b);              // ZIP2 Vd.4S,Vn.4S,Vm.4S
uint64x2_t vzip2q_u64(uint64x2_t a, uint64x2_t b);              // ZIP2 Vd.2D,Vn.2D,Vm.2D
poly64x2_t vzip2q_p64(poly64x2_t a, poly64x2_t b);              // ZIP2 Vd.2D,Vn.2D,Vm.2D
float32x2_t vzip2_f32(float32x2_t a, float32x2_t b);            // ZIP2 Vd.2S,Vn.2S,Vm.2S
float32x4_t vzip2q_f32(float32x4_t a, float32x4_t b);           // ZIP2 Vd.4S,Vn.4S,Vm.4S
float64x2_t vzip2q_f64(float64x2_t a, float64x2_t b);           // ZIP2 Vd.2D,Vn.2D,Vm.2D
poly8x8_t vzip2_p8(poly8x8_t a, poly8x8_t b);                   // ZIP2 Vd.8B,Vn.8B,Vm.8B
poly8x16_t vzip2q_p8(poly8x16_t a, poly8x16_t b);               // ZIP2 Vd.16B,Vn.16B,Vm.16B
poly16x4_t vzip2_p16(poly16x4_t a, poly16x4_t b);               // ZIP2 Vd.4H,Vn.4H,Vm.4H
poly16x8_t vzip2q_p16(poly16x8_t a, poly16x8_t b);              // ZIP2 Vd.8H,Vn.8H,Vm.8H
int8x8_t vuzp1_s8(int8x8_t a, int8x8_t b);                      // UZP1 Vd.8B,Vn.8B,Vm.8B
int8x16_t vuzp1q_s8(int8x16_t a, int8x16_t b);                  // UZP1 Vd.16B,Vn.16B,Vm.16B
int16x4_t vuzp1_s16(int16x4_t a, int16x4_t b);                  // UZP1 Vd.4H,Vn.4H,Vm.4H
int16x8_t vuzp1q_s16(int16x8_t a, int16x8_t b);                 // UZP1 Vd.8H,Vn.8H,Vm.8H
int32x2_t vuzp1_s32(int32x2_t a, int32x2_t b);                  // UZP1 Vd.2S,Vn.2S,Vm.2S
int32x4_t vuzp1q_s32(int32x4_t a, int32x4_t b);                 // UZP1 Vd.4S,Vn.4S,Vm.4S
int64x2_t vuzp1q_s64(int64x2_t a, int64x2_t b);                 // UZP1 Vd.2D,Vn.2D,Vm.2D
uint8x8_t vuzp1_u8(uint8x8_t a, uint8x8_t b);                   // UZP1 Vd.8B,Vn.8B,Vm.8B
uint8x16_t vuzp1q_u8(uint8x16_t a, uint8x16_t b);               // UZP1 Vd.16B,Vn.16B,Vm.16B
uint16x4_t vuzp1_u16(uint16x4_t a, uint16x4_t b);               // UZP1 Vd.4H,Vn.4H,Vm.4H
uint16x8_t vuzp1q_u16(uint16x8_t a, uint16x8_t b);              // UZP1 Vd.8H,Vn.8H,Vm.8H
uint32x2_t vuzp1_u32(uint32x2_t a, uint32x2_t b);               // UZP1 Vd.2S,Vn.2S,Vm.2S
uint32x4_t vuzp1q_u32(uint32x4_t a, uint32x4_t b);              // UZP1 Vd.4S,Vn.4S,Vm.4S
uint64x2_t vuzp1q_u64(uint64x2_t a, uint64x2_t b);              // UZP1 Vd.2D,Vn.2D,Vm.2D
poly64x2_t vuzp1q_p64(poly64x2_t a, poly64x2_t b);              // UZP1 Vd.2D,Vn.2D,Vm.2D
float32x2_t vuzp1_f32(float32x2_t a, float32x2_t b);            // UZP1 Vd.2S,Vn.2S,Vm.2S
float32x4_t vuzp1q_f32(float32x4_t a, float32x4_t b);           // UZP1 Vd.4S,Vn.4S,Vm.4S
float64x2_t vuzp1q_f64(float64x2_t a, float64x2_t b);           // UZP1 Vd.2D,Vn.2D,Vm.2D
poly8x8_t vuzp1_p8(poly8x8_t a, poly8x8_t b);                   // UZP1 Vd.8B,Vn.8B,Vm.8B
poly8x16_t vuzp1q_p8(poly8x16_t a, poly8x16_t b);               // UZP1 Vd.16B,Vn.16B,Vm.16B
poly16x4_t vuzp1_p16(poly16x4_t a, poly16x4_t b);               // UZP1 Vd.4H,Vn.4H,Vm.4H
poly16x8_t vuzp1q_p16(poly16x8_t a, poly16x8_t b);              // UZP1 Vd.8H,Vn.8H,Vm.8H
int8x8_t vuzp2_s8(int8x8_t a, int8x8_t b);                      // UZP2 Vd.8B,Vn.8B,Vm.8B
int8x16_t vuzp2q_s8(int8x16_t a, int8x16_t b);                  // UZP2 Vd.16B,Vn.16B,Vm.16B
int16x4_t vuzp2_s16(int16x4_t a, int16x4_t b);                  // UZP2 Vd.4H,Vn.4H,Vm.4H
int16x8_t vuzp2q_s16(int16x8_t a, int16x8_t b);                 // UZP2 Vd.8H,Vn.8H,Vm.8H
int32x2_t vuzp2_s32(int32x2_t a, int32x2_t b);                  // UZP2 Vd.2S,Vn.2S,Vm.2S
int32x4_t vuzp2q_s32(int32x4_t a, int32x4_t b);                 // UZP2 Vd.4S,Vn.4S,Vm.4S
int64x2_t vuzp2q_s64(int64x2_t a, int64x2_t b);                 // UZP2 Vd.2D,Vn.2D,Vm.2D
uint8x8_t vuzp2_u8(uint8x8_t a, uint8x8_t b);                   // UZP2 Vd.8B,Vn.8B,Vm.8B
uint8x16_t vuzp2q_u8(uint8x16_t a, uint8x16_t b);               // UZP2 Vd.16B,Vn.16B,Vm.16B
uint16x4_t vuzp2_u16(uint16x4_t a, uint16x4_t b);               // UZP2 Vd.4H,Vn.4H,Vm.4H
uint16x8_t vuzp2q_u16(uint16x8_t a, uint16x8_t b);              // UZP2 Vd.8H,Vn.8H,Vm.8H
uint32x2_t vuzp2_u32(uint32x2_t a, uint32x2_t b);               // UZP2 Vd.2S,Vn.2S,Vm.2S
uint32x4_t vuzp2q_u32(uint32x4_t a, uint32x4_t b);              // UZP2 Vd.4S,Vn.4S,Vm.4S
uint64x2_t vuzp2q_u64(uint64x2_t a, uint64x2_t b);              // UZP2 Vd.2D,Vn.2D,Vm.2D
poly64x2_t vuzp2q_p64(poly64x2_t a, poly64x2_t b);              // UZP2 Vd.2D,Vn.2D,Vm.2D
float32x2_t vuzp2_f32(float32x2_t a, float32x2_t b);            // UZP2 Vd.2S,Vn.2S,Vm.2S
float32x4_t vuzp2q_f32(float32x4_t a, float32x4_t b);           // UZP2 Vd.4S,Vn.4S,Vm.4S
float64x2_t vuzp2q_f64(float64x2_t a, float64x2_t b);           // UZP2 Vd.2D,Vn.2D,Vm.2D
poly8x8_t vuzp2_p8(poly8x8_t a, poly8x8_t b);                   // UZP2 Vd.8B,Vn.8B,Vm.8B
poly8x16_t vuzp2q_p8(poly8x16_t a, poly8x16_t b);               // UZP2 Vd.16B,Vn.16B,Vm.16B
poly16x4_t vuzp2_p16(poly16x4_t a, poly16x4_t b);               // UZP2 Vd.4H,Vn.4H,Vm.4H
poly16x8_t vuzp2q_p16(poly16x8_t a, poly16x8_t b);              // UZP2 Vd.8H,Vn.8H,Vm.8H
int8x8_t vtrn1_s8(int8x8_t a, int8x8_t b);                      // TRN1 Vd.8B,Vn.8B,Vm.8B
int8x16_t vtrn1q_s8(int8x16_t a, int8x16_t b);                  // TRN1 Vd.16B,Vn.16B,Vm.16B
int16x4_t vtrn1_s16(int16x4_t a, int16x4_t b);                  // TRN1 Vd.4H,Vn.4H,Vm.4H
int16x8_t vtrn1q_s16(int16x8_t a, int16x8_t b);                 // TRN1 Vd.8H,Vn.8H,Vm.8H
int32x2_t vtrn1_s32(int32x2_t a, int32x2_t b);                  // TRN1 Vd.2S,Vn.2S,Vm.2S
int32x4_t vtrn1q_s32(int32x4_t a, int32x4_t b);                 // TRN1 Vd.4S,Vn.4S,Vm.4S
int64x2_t vtrn1q_s64(int64x2_t a, int64x2_t b);                 // TRN1 Vd.2D,Vn.2D,Vm.2D
uint8x8_t vtrn1_u8(uint8x8_t a, uint8x8_t b);                   // TRN1 Vd.8B,Vn.8B,Vm.8B
uint8x16_t vtrn1q_u8(uint8x16_t a, uint8x16_t b);               // TRN1 Vd.16B,Vn.16B,Vm.16B
uint16x4_t vtrn1_u16(uint16x4_t a, uint16x4_t b);               // TRN1 Vd.4H,Vn.4H,Vm.4H
uint16x8_t vtrn1q_u16(uint16x8_t a, uint16x8_t b);              // TRN1 Vd.8H,Vn.8H,Vm.8H
uint32x2_t vtrn1_u32(uint32x2_t a, uint32x2_t b);               // TRN1 Vd.2S,Vn.2S,Vm.2S
uint32x4_t vtrn1q_u32(uint32x4_t a, uint32x4_t b);              // TRN1 Vd.4S,Vn.4S,Vm.4S
uint64x2_t vtrn1q_u64(uint64x2_t a, uint64x2_t b);              // TRN1 Vd.2D,Vn.2D,Vm.2D
poly64x2_t vtrn1q_p64(poly64x2_t a, poly64x2_t b);              // TRN1 Vd.2D,Vn.2D,Vm.2D
float32x2_t vtrn1_f32(float32x2_t a, float32x2_t b);            // TRN1 Vd.2S,Vn.2S,Vm.2S
float32x4_t vtrn1q_f32(float32x4_t a, float32x4_t b);           // TRN1 Vd.4S,Vn.4S,Vm.4S
float64x2_t vtrn1q_f64(float64x2_t a, float64x2_t b);           // TRN1 Vd.2D,Vn.2D,Vm.2D
poly8x8_t vtrn1_p8(poly8x8_t a, poly8x8_t b);                   // TRN1 Vd.8B,Vn.8B,Vm.8B
poly8x16_t vtrn1q_p8(poly8x16_t a, poly8x16_t b);               // TRN1 Vd.16B,Vn.16B,Vm.16B
poly16x4_t vtrn1_p16(poly16x4_t a, poly16x4_t b);               // TRN1 Vd.4H,Vn.4H,Vm.4H
poly16x8_t vtrn1q_p16(poly16x8_t a, poly16x8_t b);              // TRN1 Vd.8H,Vn.8H,Vm.8H
int8x8_t vtrn2_s8(int8x8_t a, int8x8_t b);                      // TRN2 Vd.8B,Vn.8B,Vm.8B
int8x16_t vtrn2q_s8(int8x16_t a, int8x16_t b);                  // TRN2 Vd.16B,Vn.16B,Vm.16B
int16x4_t vtrn2_s16(int16x4_t a, int16x4_t b);                  // TRN2 Vd.4H,Vn.4H,Vm.4H
int16x8_t vtrn2q_s16(int16x8_t a, int16x8_t b);                 // TRN2 Vd.8H,Vn.8H,Vm.8H
int32x2_t vtrn2_s32(int32x2_t a, int32x2_t b);                  // TRN2 Vd.2S,Vn.2S,Vm.2S
int32x4_t vtrn2q_s32(int32x4_t a, int32x4_t b);                 // TRN2 Vd.4S,Vn.4S,Vm.4S
int64x2_t vtrn2q_s64(int64x2_t a, int64x2_t b);                 // TRN2 Vd.2D,Vn.2D,Vm.2D
uint8x8_t vtrn2_u8(uint8x8_t a, uint8x8_t b);                   // TRN2 Vd.8B,Vn.8B,Vm.8B
uint8x16_t vtrn2q_u8(uint8x16_t a, uint8x16_t b);               // TRN2 Vd.16B,Vn.16B,Vm.16B
uint16x4_t vtrn2_u16(uint16x4_t a, uint16x4_t b);               // TRN2 Vd.4H,Vn.4H,Vm.4H
uint16x8_t vtrn2q_u16(uint16x8_t a, uint16x8_t b);              // TRN2 Vd.8H,Vn.8H,Vm.8H
uint32x2_t vtrn2_u32(uint32x2_t a, uint32x2_t b);               // TRN2 Vd.2S,Vn.2S,Vm.2S
uint32x4_t vtrn2q_u32(uint32x4_t a, uint32x4_t b);              // TRN2 Vd.4S,Vn.4S,Vm.4S
uint64x2_t vtrn2q_u64(uint64x2_t a, uint64x2_t b);              // TRN2 Vd.2D,Vn.2D,Vm.2D
poly64x2_t vtrn2q_p64(poly64x2_t a, poly64x2_t b);              // TRN2 Vd.2D,Vn.2D,Vm.2D
float32x2_t vtrn2_f32(float32x2_t a, float32x2_t b);            // TRN2 Vd.2S,Vn.2S,Vm.2S
float32x4_t vtrn2q_f32(float32x4_t a, float32x4_t b);           // TRN2 Vd.4S,Vn.4S,Vm.4S
float64x2_t vtrn2q_f64(float64x2_t a, float64x2_t b);           // TRN2 Vd.2D,Vn.2D,Vm.2D
poly8x8_t vtrn2_p8(poly8x8_t a, poly8x8_t b);                   // TRN2 Vd.8B,Vn.8B,Vm.8B
poly8x16_t vtrn2q_p8(poly8x16_t a, poly8x16_t b);               // TRN2 Vd.16B,Vn.16B,Vm.16B
poly16x4_t vtrn2_p16(poly16x4_t a, poly16x4_t b);               // TRN2 Vd.4H,Vn.4H,Vm.4H
poly16x8_t vtrn2q_p16(poly16x8_t a, poly16x8_t b);              // TRN2 Vd.8H,Vn.8H,Vm.8H
int8x8_t vtbl1_s8(int8x8_t a, int8x8_t idx);                    // TBL Vd.8B,{Vn.16B},Vm.8B
uint8x8_t vtbl1_u8(uint8x8_t a, uint8x8_t idx);                 // TBL Vd.8B,{Vn.16B},Vm.8B
poly8x8_t vtbl1_p8(poly8x8_t a, uint8x8_t idx);                 // TBL Vd.8B,{Vn.16B},Vm.8B
int8x8_t vtbx1_s8(
    int8x8_t a, int8x8_t b, int8x8_t idx);  // MOVI Vtmp.8B,#8; CMHS Vtmp.8B,Vm.8B,Vtmp.8B; TBL
                                            // Vtmp1.8B,{Vn.16B},Vm.8B; BIF Vd.8B,Vtmp1.8B,Vtmp.8B
uint8x8_t vtbx1_u8(uint8x8_t a, uint8x8_t b,
    uint8x8_t idx);  // MOVI Vtmp.8B,#8; CMHS Vtmp.8B,Vm.8B,Vtmp.8B; TBL Vtmp1.8B,{Vn.16B},Vm.8B;
                     // BIF Vd.8B,Vtmp1.8B,Vtmp.8B
poly8x8_t vtbx1_p8(poly8x8_t a, poly8x8_t b,
    uint8x8_t idx);  // MOVI Vtmp.8B,#8; CMHS Vtmp.8B,Vm.8B,Vtmp.8B; TBL Vtmp1.8B,{Vn.16B},Vm.8B;
                     // BIF Vd.8B,Vtmp1.8B,Vtmp.8B
int8x8_t vtbl2_s8(int8x8x2_t a, int8x8_t idx);                  // TBL Vd.8B,{Vn.16B},Vm.8B
uint8x8_t vtbl2_u8(uint8x8x2_t a, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B},Vm.8B
poly8x8_t vtbl2_p8(poly8x8x2_t a, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B},Vm.8B
int8x8_t vtbl3_s8(int8x8x3_t a, int8x8_t idx);                  // TBL Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
uint8x8_t vtbl3_u8(uint8x8x3_t a, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
poly8x8_t vtbl3_p8(poly8x8x3_t a, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
int8x8_t vtbl4_s8(int8x8x4_t a, int8x8_t idx);                  // TBL Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
uint8x8_t vtbl4_u8(uint8x8x4_t a, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
poly8x8_t vtbl4_p8(poly8x8x4_t a, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
int8x8_t vtbx2_s8(int8x8_t a, int8x8x2_t b, int8x8_t idx);      // TBX Vd.8B,{Vn.16B},Vm.8B
uint8x8_t vtbx2_u8(uint8x8_t a, uint8x8x2_t b, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B},Vm.8B
poly8x8_t vtbx2_p8(poly8x8_t a, poly8x8x2_t b, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B},Vm.8B
int8x8_t vtbx3_s8(int8x8_t a, int8x8x3_t b,
    int8x8_t idx);  // MOVI Vtmp.8B,#24; CMHS Vtmp.8B,Vm.8B,Vtmp.8B; TBL
                    // Vtmp1.8B,{Vn.16B,Vn+1.16B},Vm.8; BIF Vd.8B,Vtmp1.8B,Vtmp.8B
uint8x8_t vtbx3_u8(uint8x8_t a, uint8x8x3_t b,
    uint8x8_t idx);  // MOVI Vtmp.8B,#24; CMHS Vtmp.8B,Vm.8B,Vtmp.8B; TBL
                     // Vtmp1.8B,{Vn.16B,Vn+1.16B},Vm.8B; BIF Vd.8B,Vtmp1.8B,Vtmp.8B
poly8x8_t vtbx3_p8(poly8x8_t a, poly8x8x3_t b,
    uint8x8_t idx);  // MOVI Vtmp.8B,#24; CMHS Vtmp.8B,Vm.8B,Vtmp.8B; TBL
                     // Vtmp1.8B,{Vn.16B,Vn+1.16B},Vm.8B; BIF Vd.8B,Vtmp1.8B,Vtmp.8B
int8x8_t vtbx4_s8(int8x8_t a, int8x8x4_t b, int8x8_t idx);      // TBX Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
uint8x8_t vtbx4_u8(uint8x8_t a, uint8x8x4_t b, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
poly8x8_t vtbx4_p8(poly8x8_t a, poly8x8x4_t b, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B,Vn+1.16B},Vm.8B
int8x8_t vqtbl1_s8(int8x16_t t, uint8x8_t idx);                 // TBL Vd.8B,{Vn.16B},Vm.8B
int8x16_t vqtbl1q_s8(int8x16_t t, uint8x16_t idx);              // TBL Vd.16B,{Vn.16B},Vm.16B
uint8x8_t vqtbl1_u8(uint8x16_t t, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B},Vm.8B
uint8x16_t vqtbl1q_u8(uint8x16_t t, uint8x16_t idx);            // TBL Vd.16B,{Vn.16B},Vm.16B
poly8x8_t vqtbl1_p8(poly8x16_t t, uint8x8_t idx);               // TBL Vd.8B,{Vn.16B},Vm.8B
poly8x16_t vqtbl1q_p8(poly8x16_t t, uint8x16_t idx);            // TBL Vd.16B,{Vn.16B},Vm.16B
int8x8_t vqtbx1_s8(int8x8_t a, int8x16_t t, uint8x8_t idx);     // TBX Vd.8B,{Vn.16B},Vm.8B
int8x16_t vqtbx1q_s8(int8x16_t a, int8x16_t t, uint8x16_t idx);     // TBX Vd.16B,{Vn.16B},Vm.16B
uint8x8_t vqtbx1_u8(uint8x8_t a, uint8x16_t t, uint8x8_t idx);      // TBX Vd.8B,{Vn.16B},Vm.8B
uint8x16_t vqtbx1q_u8(uint8x16_t a, uint8x16_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B},Vm.16B
poly8x8_t vqtbx1_p8(poly8x8_t a, poly8x16_t t, uint8x8_t idx);      // TBX Vd.8B,{Vn.16B},Vm.8B
poly8x16_t vqtbx1q_p8(poly8x16_t a, poly8x16_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B},Vm.16B
int8x8_t vqtbl2_s8(int8x16x2_t t, uint8x8_t idx);       // TBL Vd.8B,{Vn.16B - Vn+1.16B},Vm.8B
int8x16_t vqtbl2q_s8(int8x16x2_t t, uint8x16_t idx);    // TBL Vd.16B,{Vn.16B - Vn+1.16B},Vm.16B
uint8x8_t vqtbl2_u8(uint8x16x2_t t, uint8x8_t idx);     // TBL Vd.8B,{Vn.16B - Vn+1.16B},Vm.8B
uint8x16_t vqtbl2q_u8(uint8x16x2_t t, uint8x16_t idx);  // TBL Vd.16B,{Vn.16B - Vn+1.16B},Vm.16B
poly8x8_t vqtbl2_p8(poly8x16x2_t t, uint8x8_t idx);     // TBL Vd.8B,{Vn.16B - Vn+1.16B},Vm.8B
poly8x16_t vqtbl2q_p8(poly8x16x2_t t, uint8x16_t idx);  // TBL Vd.16B,{Vn.16B - Vn+1.16B},Vm.16B
int8x8_t vqtbl3_s8(int8x16x3_t t, uint8x8_t idx);       // TBL Vd.8B,{Vn.16B - Vn+2.16B},Vm.8B
int8x16_t vqtbl3q_s8(int8x16x3_t t, uint8x16_t idx);    // TBL Vd.16B,{Vn.16B - Vn+2.16B},Vm.16B
uint8x8_t vqtbl3_u8(uint8x16x3_t t, uint8x8_t idx);     // TBL Vd.8B,{Vn.16B - Vn+2.16B},Vm.8B
uint8x16_t vqtbl3q_u8(uint8x16x3_t t, uint8x16_t idx);  // TBL Vd.16B,{Vn.16B - Vn+2.16B},Vm.16B
poly8x8_t vqtbl3_p8(poly8x16x3_t t, uint8x8_t idx);     // TBL Vd.8B,{Vn.16B - Vn+2.16B},Vm.8B
poly8x16_t vqtbl3q_p8(poly8x16x3_t t, uint8x16_t idx);  // TBL Vd.16B,{Vn.16B - Vn+2.16B},Vm.16B
int8x8_t vqtbl4_s8(int8x16x4_t t, uint8x8_t idx);       // TBL Vd.8B,{Vn.16B - Vn+3.16B},Vm.8B
int8x16_t vqtbl4q_s8(int8x16x4_t t, uint8x16_t idx);    // TBL Vd.16B,{Vn.16B - Vn+3.16B},Vm.16B
uint8x8_t vqtbl4_u8(uint8x16x4_t t, uint8x8_t idx);     // TBL Vd.8B,{Vn.16B - Vn+3.16B},Vm.8B
uint8x16_t vqtbl4q_u8(uint8x16x4_t t, uint8x16_t idx);  // TBL Vd.16B,{Vn.16B - Vn+3.16B},Vm.16B
poly8x8_t vqtbl4_p8(poly8x16x4_t t, uint8x8_t idx);     // TBL Vd.8B,{Vn.16B - Vn+3.16B},Vm.8B
poly8x16_t vqtbl4q_p8(poly8x16x4_t t, uint8x16_t idx);  // TBL Vd.16B,{Vn.16B - Vn+3.16B},Vm.16B
int8x8_t vqtbx2_s8(
    int8x8_t a, int8x16x2_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+1.16B},Vm.8B
int8x16_t vqtbx2q_s8(
    int8x16_t a, int8x16x2_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+1.16B},Vm.16B
uint8x8_t vqtbx2_u8(
    uint8x8_t a, uint8x16x2_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+1.16B},Vm.8B
uint8x16_t vqtbx2q_u8(
    uint8x16_t a, uint8x16x2_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+1.16B},Vm.16B
poly8x8_t vqtbx2_p8(
    poly8x8_t a, poly8x16x2_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+1.16B},Vm.8B
poly8x16_t vqtbx2q_p8(
    poly8x16_t a, poly8x16x2_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+1.16B},Vm.16B
int8x8_t vqtbx3_s8(
    int8x8_t a, int8x16x3_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+2.16B},Vm.8B
int8x16_t vqtbx3q_s8(
    int8x16_t a, int8x16x3_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+2.16B},Vm.16B
uint8x8_t vqtbx3_u8(
    uint8x8_t a, uint8x16x3_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+2.16B},Vm.8B
uint8x16_t vqtbx3q_u8(
    uint8x16_t a, uint8x16x3_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+2.16B},Vm.16B
poly8x8_t vqtbx3_p8(
    poly8x8_t a, poly8x16x3_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+2.16B},Vm.8B
poly8x16_t vqtbx3q_p8(
    poly8x16_t a, poly8x16x3_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+2.16B},Vm.16B
int8x8_t vqtbx4_s8(
    int8x8_t a, int8x16x4_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+3.16B},Vm.8B
int8x16_t vqtbx4q_s8(
    int8x16_t a, int8x16x4_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+3.16B},Vm.16B
uint8x8_t vqtbx4_u8(
    uint8x8_t a, uint8x16x4_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+3.16B},Vm.8B
uint8x16_t vqtbx4q_u8(
    uint8x16_t a, uint8x16x4_t t, uint8x16_t idx);  // TBX Vd.16B,{Vn.16B - Vn+3.16B},Vm.16B
poly8x8_t vqtbx4_p8(
    poly8x8_t a, poly8x16x4_t t, uint8x8_t idx);  // TBX Vd.8B,{Vn.16B - Vn+3.16B},Vm.8B
poly8x16_t vqtbx4q_p8(
    poly8x16_t a, poly8x16x4_t t, uint8x16_t idx);        // TBX Vd.16B,{Vn.16B - Vn+3.16B},Vm.16B
uint8_t vget_lane_u8(uint8x8_t v, const int lane);        // UMOV Rd,Vn.B[lane]
uint16_t vget_lane_u16(uint16x4_t v, const int lane);     // UMOV Rd,Vn.H[lane]
uint32_t vget_lane_u32(uint32x2_t v, const int lane);     // UMOV Rd,Vn.S[lane]
uint64_t vget_lane_u64(uint64x1_t v, const int lane);     // UMOV Rd,Vn.D[lane]
poly64_t vget_lane_p64(poly64x1_t v, const int lane);     // UMOV Rd,Vn.D[lane]
int8_t vget_lane_s8(int8x8_t v, const int lane);          // SMOV Rd,Vn.B[lane]
int16_t vget_lane_s16(int16x4_t v, const int lane);       // SMOV Rd,Vn.H[lane]
int32_t vget_lane_s32(int32x2_t v, const int lane);       // SMOV Rd,Vn.S[lane]
int64_t vget_lane_s64(int64x1_t v, const int lane);       // UMOV Rd,Vn.D[lane]
poly8_t vget_lane_p8(poly8x8_t v, const int lane);        // UMOV Rd,Vn.B[lane]
poly16_t vget_lane_p16(poly16x4_t v, const int lane);     // UMOV Rd,Vn.H[lane]
float32_t vget_lane_f32(float32x2_t v, const int lane);   // DUP Sd,Vn.S[lane]
float64_t vget_lane_f64(float64x1_t v, const int lane);   // DUP Dd,Vn.D[lane]
uint8_t vgetq_lane_u8(uint8x16_t v, const int lane);      // UMOV Rd,Vn.B[lane]
uint16_t vgetq_lane_u16(uint16x8_t v, const int lane);    // UMOV Rd,Vn.H[lane]
uint32_t vgetq_lane_u32(uint32x4_t v, const int lane);    // UMOV Rd,Vn.S[lane]
uint64_t vgetq_lane_u64(uint64x2_t v, const int lane);    // UMOV Rd,Vn.D[lane]
poly64_t vgetq_lane_p64(poly64x2_t v, const int lane);    // UMOV Rd,Vn.D[lane]
int8_t vgetq_lane_s8(int8x16_t v, const int lane);        // SMOV Rd,Vn.B[lane]
int16_t vgetq_lane_s16(int16x8_t v, const int lane);      // SMOV Rd,Vn.H[lane]
int32_t vgetq_lane_s32(int32x4_t v, const int lane);      // SMOV Rd,Vn.S[lane]
int64_t vgetq_lane_s64(int64x2_t v, const int lane);      // UMOV Rd,Vn.D[lane]
poly8_t vgetq_lane_p8(poly8x16_t v, const int lane);      // UMOV Rd,Vn.B[lane]
poly16_t vgetq_lane_p16(poly16x8_t v, const int lane);    // UMOV Rd,Vn.H[lane]
float16_t vget_lane_f16(float16x4_t v, const int lane);   // DUP Hd,Vn.H[lane]
float16_t vgetq_lane_f16(float16x8_t v, const int lane);  // DUP Hd,Vn.H[lane]
float32_t vgetq_lane_f32(float32x4_t v, const int lane);  // DUP Sd,Vn.S[lane]
float64_t vgetq_lane_f64(float64x2_t v, const int lane);  // DUP Dd,Vn.D[lane]
uint8x8_t vset_lane_u8(uint8_t a, uint8x8_t v, const int lane);          // MOV Vd.B[lane],Rn
uint16x4_t vset_lane_u16(uint16_t a, uint16x4_t v, const int lane);      // MOV Vd.H[lane],Rn
uint32x2_t vset_lane_u32(uint32_t a, uint32x2_t v, const int lane);      // MOV Vd.S[lane],Rn
uint64x1_t vset_lane_u64(uint64_t a, uint64x1_t v, const int lane);      // MOV Vd.D[lane],Rn
poly64x1_t vset_lane_p64(poly64_t a, poly64x1_t v, const int lane);      // MOV Vd.D[lane],Rn
int8x8_t vset_lane_s8(int8_t a, int8x8_t v, const int lane);             // MOV Vd.B[lane],Rn
int16x4_t vset_lane_s16(int16_t a, int16x4_t v, const int lane);         // MOV Vd.H[lane],Rn
int32x2_t vset_lane_s32(int32_t a, int32x2_t v, const int lane);         // MOV Vd.S[lane],Rn
int64x1_t vset_lane_s64(int64_t a, int64x1_t v, const int lane);         // MOV Vd.D[lane],Rn
poly8x8_t vset_lane_p8(poly8_t a, poly8x8_t v, const int lane);          // MOV Vd.B[lane],Rn
poly16x4_t vset_lane_p16(poly16_t a, poly16x4_t v, const int lane);      // MOV Vd.H[lane],Rn
float16x4_t vset_lane_f16(float16_t a, float16x4_t v, const int lane);   // MOV Vd.H[lane],Vn.H[0]
float16x8_t vsetq_lane_f16(float16_t a, float16x8_t v, const int lane);  // MOV Vd.H[lane],Vn.H[0]
float32x2_t vset_lane_f32(float32_t a, float32x2_t v, const int lane);   // MOV Vd.S[lane],Rn
float64x1_t vset_lane_f64(float64_t a, float64x1_t v, const int lane);   // MOV Vd.D[lane],Rn
uint8x16_t vsetq_lane_u8(uint8_t a, uint8x16_t v, const int lane);       // MOV Vd.B[lane],Rn
uint16x8_t vsetq_lane_u16(uint16_t a, uint16x8_t v, const int lane);     // MOV Vd.H[lane],Rn
uint32x4_t vsetq_lane_u32(uint32_t a, uint32x4_t v, const int lane);     // MOV Vd.S[lane],Rn
uint64x2_t vsetq_lane_u64(uint64_t a, uint64x2_t v, const int lane);     // MOV Vd.D[lane],Rn
poly64x2_t vsetq_lane_p64(poly64_t a, poly64x2_t v, const int lane);     // MOV Vd.D[lane],Rn
int8x16_t vsetq_lane_s8(int8_t a, int8x16_t v, const int lane);          // MOV Vd.B[lane],Rn
int16x8_t vsetq_lane_s16(int16_t a, int16x8_t v, const int lane);        // MOV Vd.H[lane],Rn
int32x4_t vsetq_lane_s32(int32_t a, int32x4_t v, const int lane);        // MOV Vd.S[lane],Rn
int64x2_t vsetq_lane_s64(int64_t a, int64x2_t v, const int lane);        // MOV Vd.D[lane],Rn
poly8x16_t vsetq_lane_p8(poly8_t a, poly8x16_t v, const int lane);       // MOV Vd.B[lane],Rn
poly16x8_t vsetq_lane_p16(poly16_t a, poly16x8_t v, const int lane);     // MOV Vd.H[lane],Rn
float32x4_t vsetq_lane_f32(float32_t a, float32x4_t v, const int lane);  // MOV Vd.S[lane],Rn
float64x2_t vsetq_lane_f64(float64_t a, float64x2_t v, const int lane);  // MOV Vd.D[lane],Rn
float32_t vrecpxs_f32(float32_t a);                                      // FRECPX Sd,Sn
float64_t vrecpxd_f64(float64_t a);                                      // FRECPX Dd,Dn
float32x2_t vfma_n_f32(float32x2_t a, float32x2_t b, float32_t n);       // FMLA Vd.2S,Vn.2S,Vm.S[0]
float32x4_t vfmaq_n_f32(float32x4_t a, float32x4_t b, float32_t n);      // FMLA Vd.4S,Vn.4S,Vm.S[0]
float32x2_t vfms_n_f32(float32x2_t a, float32x2_t b, float32_t n);       // FMLS Vd.2S,Vn.2S,Vm.S[0]
float32x4_t vfmsq_n_f32(float32x4_t a, float32x4_t b, float32_t n);      // FMLS Vd.4S,Vn.4S,Vm.S[0]
float64x1_t vfma_n_f64(float64x1_t a, float64x1_t b, float64_t n);       // FMADD Dd,Dn,Dm,Da
float64x2_t vfmaq_n_f64(float64x2_t a, float64x2_t b, float64_t n);      // FMLA Vd.2D,Vn.2D,Vm.D[0]
float64x1_t vfms_n_f64(float64x1_t a, float64x1_t b, float64_t n);       // FMSUB Dd,Dn,Dm,Da
float64x2_t vfmsq_n_f64(float64x2_t a, float64x2_t b, float64_t n);      // FMLS Vd.2D,Vn.2D,Vm.D[0]
int8x8x2_t vtrn_s8(int8x8_t a, int8x8_t b);      // TRN1 Vd1.8B,Vn.8B,Vm.8B; TRN2 Vd2.8B,Vn.8B,Vm.8B
int16x4x2_t vtrn_s16(int16x4_t a, int16x4_t b);  // TRN1 Vd1.4H,Vn.4H,Vm.4H; TRN2 Vd2.4H,Vn.4H,Vm.4H
uint8x8x2_t vtrn_u8(uint8x8_t a, uint8x8_t b);   // TRN1 Vd1.8B,Vn.8B,Vm.8B; TRN2 Vd2.8B,Vn.8B,Vm.8B
uint16x4x2_t vtrn_u16(
    uint16x4_t a, uint16x4_t b);                // TRN1 Vd1.4H,Vn.4H,Vm.4H; TRN2 Vd2.4H,Vn.4H,Vm.4H
poly8x8x2_t vtrn_p8(poly8x8_t a, poly8x8_t b);  // TRN1 Vd1.8B,Vn.8B,Vm.8B; TRN2 Vd2.8B,Vn.8B,Vm.8B
poly16x4x2_t vtrn_p16(
    poly16x4_t a, poly16x4_t b);                 // TRN1 Vd1.4H,Vn.4H,Vm.4H; TRN2 Vd2.4H,Vn.4H,Vm.4H
int32x2x2_t vtrn_s32(int32x2_t a, int32x2_t b);  // TRN1 Vd1.2S,Vn.2S,Vm.2S; TRN2 Vd2.2S,Vn.2S,Vm.2S
float32x2x2_t vtrn_f32(
    float32x2_t a, float32x2_t b);  // TRN1 Vd1.2S,Vn.2S,Vm.2S; TRN2 Vd2.2S,Vn.2S,Vm.2S
uint32x2x2_t vtrn_u32(
    uint32x2_t a, uint32x2_t b);  // TRN1 Vd1.2S,Vn.2S,Vm.2S; TRN2 Vd2.2S,Vn.2S,Vm.2S
int8x16x2_t vtrnq_s8(
    int8x16_t a, int8x16_t b);  // TRN1 Vd1.16B,Vn.16B,Vm.16B; TRN2 Vd2.16B,Vn.16B,Vm.16B
int16x8x2_t vtrnq_s16(
    int16x8_t a, int16x8_t b);  // TRN1 Vd1.8H,Vn.8H,Vm.8H; TRN2 Vd2.8H,Vn.8H,Vm.8H
int32x4x2_t vtrnq_s32(
    int32x4_t a, int32x4_t b);  // TRN1 Vd1.4S,Vn.4S,Vm.4S; TRN2 Vd2.4S,Vn.4S,Vm.4S
float32x4x2_t vtrnq_f32(
    float32x4_t a, float32x4_t b);  // TRN1 Vd1.4S,Vn.4S,Vm.4S; TRN2 Vd2.4S,Vn.4S,Vm.4S
uint8x16x2_t vtrnq_u8(
    uint8x16_t a, uint8x16_t b);  // TRN1 Vd1.16B,Vn.16B,Vm.16B; TRN2 Vd2.16B,Vn.16B,Vm.16B
uint16x8x2_t vtrnq_u16(
    uint16x8_t a, uint16x8_t b);  // TRN1 Vd1.8H,Vn.8H,Vm.8H; TRN2 Vd2.8H,Vn.8H,Vm.8H
uint32x4x2_t vtrnq_u32(
    uint32x4_t a, uint32x4_t b);  // TRN1 Vd1.4S,Vn.4S,Vm.4S; TRN2 Vd2.4S,Vn.4S,Vm.4S
poly8x16x2_t vtrnq_p8(
    poly8x16_t a, poly8x16_t b);  // TRN1 Vd1.16B,Vn.16B,Vm.16B; TRN2 Vd2.16B,Vn.16B,Vm.16B
poly16x8x2_t vtrnq_p16(
    poly16x8_t a, poly16x8_t b);                 // TRN1 Vd1.8H,Vn.8H,Vm.8H; TRN2 Vd2.8H,Vn.8H,Vm.8H
int8x8x2_t vzip_s8(int8x8_t a, int8x8_t b);      // ZIP1 Vd1.8B,Vn.8B,Vm.8B; ZIP2 Vd2.8B,Vn.8B,Vm.8B
int16x4x2_t vzip_s16(int16x4_t a, int16x4_t b);  // ZIP1 Vd1.4H,Vn.4H,Vm.4H; ZIP2 Vd2.4H,Vn.4H,Vm.4H
uint8x8x2_t vzip_u8(uint8x8_t a, uint8x8_t b);   // ZIP1 Vd1.8B,Vn.8B,Vm.8B; ZIP2 Vd2.8B,Vn.8B,Vm.8B
uint16x4x2_t vzip_u16(
    uint16x4_t a, uint16x4_t b);                // ZIP1 Vd1.4H,Vn.4H,Vm.4H; ZIP2 Vd2.4H,Vn.4H,Vm.4H
poly8x8x2_t vzip_p8(poly8x8_t a, poly8x8_t b);  // ZIP1 Vd1.8B,Vn.8B,Vm.8B; ZIP2 Vd2.8B,Vn.8B,Vm.8B
poly16x4x2_t vzip_p16(
    poly16x4_t a, poly16x4_t b);                 // ZIP1 Vd1.4H,Vn.4H,Vm.4H; ZIP2 Vd2.4H,Vn.4H,Vm.4H
int32x2x2_t vzip_s32(int32x2_t a, int32x2_t b);  // ZIP1 Vd1.2S,Vn.2S,Vm.2S; ZIP2 Vd2.2S,Vn.2S,Vm.2S
float32x2x2_t vzip_f32(
    float32x2_t a, float32x2_t b);  // ZIP1 Vd1.2S,Vn.2S,Vm.2S; ZIP2 Vd2.2S,Vn.2S,Vm.2S
uint32x2x2_t vzip_u32(
    uint32x2_t a, uint32x2_t b);  // ZIP1 Vd1.2S,Vn.2S,Vm.2S; ZIP2 Vd2.2S,Vn.2S,Vm.2S
int8x16x2_t vzipq_s8(
    int8x16_t a, int8x16_t b);  // ZIP1 Vd1.16B,Vn.16B,Vm.16B; ZIP2 Vd2.16B,Vn.16B,Vm.16B
int16x8x2_t vzipq_s16(
    int16x8_t a, int16x8_t b);  // ZIP1 Vd1.8H,Vn.8H,Vm.8H; ZIP2 Vd2.8H,Vn.8H,Vm.8H
int32x4x2_t vzipq_s32(
    int32x4_t a, int32x4_t b);  // ZIP1 Vd1.4S,Vn.4S,Vm.4S; ZIP2 Vd2.4S,Vn.4S,Vm.4S
float32x4x2_t vzipq_f32(
    float32x4_t a, float32x4_t b);  // ZIP1 Vd1.4S,Vn.4S,Vm.4S; ZIP2 Vd2.4S,Vn.4S,Vm.4S
uint8x16x2_t vzipq_u8(
    uint8x16_t a, uint8x16_t b);  // ZIP1 Vd1.16B,Vn.16B,Vm.16B; ZIP2 Vd2.16B,Vn.16B,Vm.16B
uint16x8x2_t vzipq_u16(
    uint16x8_t a, uint16x8_t b);  // ZIP1 Vd1.8H,Vn.8H,Vm.8H; ZIP2 Vd2.8H,Vn.8H,Vm.8H
uint32x4x2_t vzipq_u32(
    uint32x4_t a, uint32x4_t b);  // ZIP1 Vd1.4S,Vn.4S,Vm.4S; ZIP2 Vd2.4S,Vn.4S,Vm.4S
poly8x16x2_t vzipq_p8(
    poly8x16_t a, poly8x16_t b);  // ZIP1 Vd1.16B,Vn.16B,Vm.16B; ZIP2 Vd2.16B,Vn.16B,Vm.16B
poly16x8x2_t vzipq_p16(
    poly16x8_t a, poly16x8_t b);                 // ZIP1 Vd1.8H,Vn.8H,Vm.8H; ZIP2 Vd2.8H,Vn.8H,Vm.8H
int8x8x2_t vuzp_s8(int8x8_t a, int8x8_t b);      // UZP1 Vd1.8B,Vn.8B,Vm.8B; UZP2 Vd2.8B,Vn.8B,Vm.8B
int16x4x2_t vuzp_s16(int16x4_t a, int16x4_t b);  // UZP1 Vd1.4H,Vn.4H,Vm.4H; UZP2 Vd2.4H,Vn.4H,Vm.4H
int32x2x2_t vuzp_s32(int32x2_t a, int32x2_t b);  // UZP1 Vd1.2S,Vn.2S,Vm.2S; UZP2 Vd2.2S,Vn.2S,Vm.2S
float32x2x2_t vuzp_f32(
    float32x2_t a, float32x2_t b);              // UZP1 Vd1.2S,Vn.2S,Vm.2S; UZP2 Vd2.2S,Vn.2S,Vm.2S
uint8x8x2_t vuzp_u8(uint8x8_t a, uint8x8_t b);  // UZP1 Vd1.8B,Vn.8B,Vm.8B; UZP2 Vd2.8B,Vn.8B,Vm.8B
uint16x4x2_t vuzp_u16(
    uint16x4_t a, uint16x4_t b);  // UZP1 Vd1.4H,Vn.4H,Vm.4H; UZP2 Vd2.4H,Vn.4H,Vm.4H
uint32x2x2_t vuzp_u32(
    uint32x2_t a, uint32x2_t b);                // UZP1 Vd1.2S,Vn.2S,Vm.2S; UZP2 Vd2.2S,Vn.2S,Vm.2S
poly8x8x2_t vuzp_p8(poly8x8_t a, poly8x8_t b);  // UZP1 Vd1.8B,Vn.8B,Vm.8B; UZP2 Vd2.8B,Vn.8B,Vm.8B
poly16x4x2_t vuzp_p16(
    poly16x4_t a, poly16x4_t b);  // UZP1 Vd1.4H,Vn.4H,Vm.4H; UZP2 Vd2.4H,Vn.4H,Vm.4H
int8x16x2_t vuzpq_s8(
    int8x16_t a, int8x16_t b);  // UZP1 Vd1.16B,Vn.16B,Vm.16B; UZP2 Vd2.16B,Vn.16B,Vm.16B
int16x8x2_t vuzpq_s16(
    int16x8_t a, int16x8_t b);  // UZP1 Vd1.8H,Vn.8H,Vm.8H; UZP2 Vd2.8H,Vn.8H,Vm.8H
int32x4x2_t vuzpq_s32(
    int32x4_t a, int32x4_t b);  // UZP1 Vd1.4S,Vn.4S,Vm.4S; UZP2 Vd2.4S,Vn.4S,Vm.4S
float32x4x2_t vuzpq_f32(
    float32x4_t a, float32x4_t b);  // UZP1 Vd1.4S,Vn.4S,Vm.4S; UZP2 Vd2.4S,Vn.4S,Vm.4S
uint8x16x2_t vuzpq_u8(
    uint8x16_t a, uint8x16_t b);  // UZP1 Vd1.16B,Vn.16B,Vm.16B; UZP2 Vd2.16B,Vn.16B,Vm.16B
uint16x8x2_t vuzpq_u16(
    uint16x8_t a, uint16x8_t b);  // UZP1 Vd1.8H,Vn.8H,Vm.8H; UZP2 Vd2.8H,Vn.8H,Vm.8H
uint32x4x2_t vuzpq_u32(
    uint32x4_t a, uint32x4_t b);  // UZP1 Vd1.4S,Vn.4S,Vm.4S; UZP2 Vd2.4S,Vn.4S,Vm.4S
poly8x16x2_t vuzpq_p8(
    poly8x16_t a, poly8x16_t b);  // UZP1 Vd1.16B,Vn.16B,Vm.16B; UZP2 Vd2.16B,Vn.16B,Vm.16B
poly16x8x2_t vuzpq_p16(
    poly16x8_t a, poly16x8_t b);                 // UZP1 Vd1.8H,Vn.8H,Vm.8H; UZP2 Vd2.8H,Vn.8H,Vm.8H
int16x4_t vreinterpret_s16_s8(int8x8_t a);       //
int32x2_t vreinterpret_s32_s8(int8x8_t a);       //
float32x2_t vreinterpret_f32_s8(int8x8_t a);     //
uint8x8_t vreinterpret_u8_s8(int8x8_t a);        //
uint16x4_t vreinterpret_u16_s8(int8x8_t a);      //
uint32x2_t vreinterpret_u32_s8(int8x8_t a);      //
poly8x8_t vreinterpret_p8_s8(int8x8_t a);        //
poly16x4_t vreinterpret_p16_s8(int8x8_t a);      //
uint64x1_t vreinterpret_u64_s8(int8x8_t a);      //
int64x1_t vreinterpret_s64_s8(int8x8_t a);       //
float64x1_t vreinterpret_f64_s8(int8x8_t a);     //
poly64x1_t vreinterpret_p64_s8(int8x8_t a);      //
float16x4_t vreinterpret_f16_s8(int8x8_t a);     //
int8x8_t vreinterpret_s8_s16(int16x4_t a);       //
int32x2_t vreinterpret_s32_s16(int16x4_t a);     //
float32x2_t vreinterpret_f32_s16(int16x4_t a);   //
uint8x8_t vreinterpret_u8_s16(int16x4_t a);      //
uint16x4_t vreinterpret_u16_s16(int16x4_t a);    //
uint32x2_t vreinterpret_u32_s16(int16x4_t a);    //
poly8x8_t vreinterpret_p8_s16(int16x4_t a);      //
poly16x4_t vreinterpret_p16_s16(int16x4_t a);    //
uint64x1_t vreinterpret_u64_s16(int16x4_t a);    //
int64x1_t vreinterpret_s64_s16(int16x4_t a);     //
float64x1_t vreinterpret_f64_s16(int16x4_t a);   //
poly64x1_t vreinterpret_p64_s16(int16x4_t a);    //
float16x4_t vreinterpret_f16_s16(int16x4_t a);   //
int8x8_t vreinterpret_s8_s32(int32x2_t a);       //
int16x4_t vreinterpret_s16_s32(int32x2_t a);     //
float32x2_t vreinterpret_f32_s32(int32x2_t a);   //
uint8x8_t vreinterpret_u8_s32(int32x2_t a);      //
uint16x4_t vreinterpret_u16_s32(int32x2_t a);    //
uint32x2_t vreinterpret_u32_s32(int32x2_t a);    //
poly8x8_t vreinterpret_p8_s32(int32x2_t a);      //
poly16x4_t vreinterpret_p16_s32(int32x2_t a);    //
uint64x1_t vreinterpret_u64_s32(int32x2_t a);    //
int64x1_t vreinterpret_s64_s32(int32x2_t a);     //
float64x1_t vreinterpret_f64_s32(int32x2_t a);   //
poly64x1_t vreinterpret_p64_s32(int32x2_t a);    //
float16x4_t vreinterpret_f16_s32(int32x2_t a);   //
int8x8_t vreinterpret_s8_f32(float32x2_t a);     //
int16x4_t vreinterpret_s16_f32(float32x2_t a);   //
int32x2_t vreinterpret_s32_f32(float32x2_t a);   //
uint8x8_t vreinterpret_u8_f32(float32x2_t a);    //
uint16x4_t vreinterpret_u16_f32(float32x2_t a);  //
uint32x2_t vreinterpret_u32_f32(float32x2_t a);  //
poly8x8_t vreinterpret_p8_f32(float32x2_t a);    //
poly16x4_t vreinterpret_p16_f32(float32x2_t a);  //
uint64x1_t vreinterpret_u64_f32(float32x2_t a);  //
int64x1_t vreinterpret_s64_f32(float32x2_t a);   //
float64x1_t vreinterpret_f64_f32(float32x2_t a);        //
poly64x1_t vreinterpret_p64_f32(float32x2_t a);         //
poly64x1_t vreinterpret_p64_f64(float64x1_t a);         //
float16x4_t vreinterpret_f16_f32(float32x2_t a);        //
int8x8_t vreinterpret_s8_u8(uint8x8_t a);               //
int16x4_t vreinterpret_s16_u8(uint8x8_t a);             //
int32x2_t vreinterpret_s32_u8(uint8x8_t a);             //
float32x2_t vreinterpret_f32_u8(uint8x8_t a);           //
uint16x4_t vreinterpret_u16_u8(uint8x8_t a);            //
uint32x2_t vreinterpret_u32_u8(uint8x8_t a);            //
poly8x8_t vreinterpret_p8_u8(uint8x8_t a);              //
poly16x4_t vreinterpret_p16_u8(uint8x8_t a);            //
uint64x1_t vreinterpret_u64_u8(uint8x8_t a);            //
int64x1_t vreinterpret_s64_u8(uint8x8_t a);             //
float64x1_t vreinterpret_f64_u8(uint8x8_t a);           //
poly64x1_t vreinterpret_p64_u8(uint8x8_t a);            //
float16x4_t vreinterpret_f16_u8(uint8x8_t a);           //
int8x8_t vreinterpret_s8_u16(uint16x4_t a);             //
int16x4_t vreinterpret_s16_u16(uint16x4_t a);           //
int32x2_t vreinterpret_s32_u16(uint16x4_t a);           //
float32x2_t vreinterpret_f32_u16(uint16x4_t a);         //
uint8x8_t vreinterpret_u8_u16(uint16x4_t a);            //
uint32x2_t vreinterpret_u32_u16(uint16x4_t a);          //
poly8x8_t vreinterpret_p8_u16(uint16x4_t a);            //
poly16x4_t vreinterpret_p16_u16(uint16x4_t a);          //
uint64x1_t vreinterpret_u64_u16(uint16x4_t a);          //
int64x1_t vreinterpret_s64_u16(uint16x4_t a);           //
float64x1_t vreinterpret_f64_u16(uint16x4_t a);         //
poly64x1_t vreinterpret_p64_u16(uint16x4_t a);          //
float16x4_t vreinterpret_f16_u16(uint16x4_t a);         //
int8x8_t vreinterpret_s8_u32(uint32x2_t a);             //
int16x4_t vreinterpret_s16_u32(uint32x2_t a);           //
int32x2_t vreinterpret_s32_u32(uint32x2_t a);           //
float32x2_t vreinterpret_f32_u32(uint32x2_t a);         //
uint8x8_t vreinterpret_u8_u32(uint32x2_t a);            //
uint16x4_t vreinterpret_u16_u32(uint32x2_t a);          //
poly8x8_t vreinterpret_p8_u32(uint32x2_t a);            //
poly16x4_t vreinterpret_p16_u32(uint32x2_t a);          //
uint64x1_t vreinterpret_u64_u32(uint32x2_t a);          //
int64x1_t vreinterpret_s64_u32(uint32x2_t a);           //
float64x1_t vreinterpret_f64_u32(uint32x2_t a);         //
poly64x1_t vreinterpret_p64_u32(uint32x2_t a);          //
float16x4_t vreinterpret_f16_u32(uint32x2_t a);         //
int8x8_t vreinterpret_s8_p8(poly8x8_t a);               //
int16x4_t vreinterpret_s16_p8(poly8x8_t a);             //
int32x2_t vreinterpret_s32_p8(poly8x8_t a);             //
float32x2_t vreinterpret_f32_p8(poly8x8_t a);           //
uint8x8_t vreinterpret_u8_p8(poly8x8_t a);              //
uint16x4_t vreinterpret_u16_p8(poly8x8_t a);            //
uint32x2_t vreinterpret_u32_p8(poly8x8_t a);            //
poly16x4_t vreinterpret_p16_p8(poly8x8_t a);            //
uint64x1_t vreinterpret_u64_p8(poly8x8_t a);            //
int64x1_t vreinterpret_s64_p8(poly8x8_t a);             //
float64x1_t vreinterpret_f64_p8(poly8x8_t a);           //
poly64x1_t vreinterpret_p64_p8(poly8x8_t a);            //
float16x4_t vreinterpret_f16_p8(poly8x8_t a);           //
int8x8_t vreinterpret_s8_p16(poly16x4_t a);             //
int16x4_t vreinterpret_s16_p16(poly16x4_t a);           //
int32x2_t vreinterpret_s32_p16(poly16x4_t a);           //
float32x2_t vreinterpret_f32_p16(poly16x4_t a);         //
uint8x8_t vreinterpret_u8_p16(poly16x4_t a);            //
uint16x4_t vreinterpret_u16_p16(poly16x4_t a);          //
uint32x2_t vreinterpret_u32_p16(poly16x4_t a);          //
poly8x8_t vreinterpret_p8_p16(poly16x4_t a);            //
uint64x1_t vreinterpret_u64_p16(poly16x4_t a);          //
int64x1_t vreinterpret_s64_p16(poly16x4_t a);           //
float64x1_t vreinterpret_f64_p16(poly16x4_t a);         //
poly64x1_t vreinterpret_p64_p16(poly16x4_t a);          //
float16x4_t vreinterpret_f16_p16(poly16x4_t a);         //
int8x8_t vreinterpret_s8_u64(uint64x1_t a);             //
int16x4_t vreinterpret_s16_u64(uint64x1_t a);           //
int32x2_t vreinterpret_s32_u64(uint64x1_t a);           //
float32x2_t vreinterpret_f32_u64(uint64x1_t a);         //
uint8x8_t vreinterpret_u8_u64(uint64x1_t a);            //
uint16x4_t vreinterpret_u16_u64(uint64x1_t a);          //
uint32x2_t vreinterpret_u32_u64(uint64x1_t a);          //
poly8x8_t vreinterpret_p8_u64(uint64x1_t a);            //
poly16x4_t vreinterpret_p16_u64(uint64x1_t a);          //
int64x1_t vreinterpret_s64_u64(uint64x1_t a);           //
float64x1_t vreinterpret_f64_u64(uint64x1_t a);         //
poly64x1_t vreinterpret_p64_u64(uint64x1_t a);          //
float16x4_t vreinterpret_f16_u64(uint64x1_t a);         //
int8x8_t vreinterpret_s8_s64(int64x1_t a);              //
int16x4_t vreinterpret_s16_s64(int64x1_t a);            //
int32x2_t vreinterpret_s32_s64(int64x1_t a);            //
float32x2_t vreinterpret_f32_s64(int64x1_t a);          //
uint8x8_t vreinterpret_u8_s64(int64x1_t a);             //
uint16x4_t vreinterpret_u16_s64(int64x1_t a);           //
uint32x2_t vreinterpret_u32_s64(int64x1_t a);           //
poly8x8_t vreinterpret_p8_s64(int64x1_t a);             //
poly16x4_t vreinterpret_p16_s64(int64x1_t a);           //
uint64x1_t vreinterpret_u64_s64(int64x1_t a);           //
float64x1_t vreinterpret_f64_s64(int64x1_t a);          //
uint64x1_t vreinterpret_u64_p64(poly64x1_t a);          //
float16x4_t vreinterpret_f16_s64(int64x1_t a);          //
int8x8_t vreinterpret_s8_f16(float16x4_t a);            //
int16x4_t vreinterpret_s16_f16(float16x4_t a);          //
int32x2_t vreinterpret_s32_f16(float16x4_t a);          //
float32x2_t vreinterpret_f32_f16(float16x4_t a);        //
uint8x8_t vreinterpret_u8_f16(float16x4_t a);           //
uint16x4_t vreinterpret_u16_f16(float16x4_t a);         //
uint32x2_t vreinterpret_u32_f16(float16x4_t a);         //
poly8x8_t vreinterpret_p8_f16(float16x4_t a);           //
poly16x4_t vreinterpret_p16_f16(float16x4_t a);         //
uint64x1_t vreinterpret_u64_f16(float16x4_t a);         //
int64x1_t vreinterpret_s64_f16(float16x4_t a);          //
float64x1_t vreinterpret_f64_f16(float16x4_t a);        //
poly64x1_t vreinterpret_p64_f16(float16x4_t a);         //
int16x8_t vreinterpretq_s16_s8(int8x16_t a);            //
int32x4_t vreinterpretq_s32_s8(int8x16_t a);            //
float32x4_t vreinterpretq_f32_s8(int8x16_t a);          //
uint8x16_t vreinterpretq_u8_s8(int8x16_t a);            //
uint16x8_t vreinterpretq_u16_s8(int8x16_t a);           //
uint32x4_t vreinterpretq_u32_s8(int8x16_t a);           //
poly8x16_t vreinterpretq_p8_s8(int8x16_t a);            //
poly16x8_t vreinterpretq_p16_s8(int8x16_t a);           //
uint64x2_t vreinterpretq_u64_s8(int8x16_t a);           //
int64x2_t vreinterpretq_s64_s8(int8x16_t a);            //
float64x2_t vreinterpretq_f64_s8(int8x16_t a);          //
poly64x2_t vreinterpretq_p64_s8(int8x16_t a);           //
poly128_t vreinterpretq_p128_s8(int8x16_t a);           //
float16x8_t vreinterpretq_f16_s8(int8x16_t a);          //
int8x16_t vreinterpretq_s8_s16(int16x8_t a);            //
int32x4_t vreinterpretq_s32_s16(int16x8_t a);           //
float32x4_t vreinterpretq_f32_s16(int16x8_t a);         //
uint8x16_t vreinterpretq_u8_s16(int16x8_t a);           //
uint16x8_t vreinterpretq_u16_s16(int16x8_t a);          //
uint32x4_t vreinterpretq_u32_s16(int16x8_t a);          //
poly8x16_t vreinterpretq_p8_s16(int16x8_t a);           //
poly16x8_t vreinterpretq_p16_s16(int16x8_t a);          //
uint64x2_t vreinterpretq_u64_s16(int16x8_t a);          //
int64x2_t vreinterpretq_s64_s16(int16x8_t a);           //
float64x2_t vreinterpretq_f64_s16(int16x8_t a);         //
poly64x2_t vreinterpretq_p64_s16(int16x8_t a);          //
poly128_t vreinterpretq_p128_s16(int16x8_t a);          //
float16x8_t vreinterpretq_f16_s16(int16x8_t a);         //
int8x16_t vreinterpretq_s8_s32(int32x4_t a);            //
int16x8_t vreinterpretq_s16_s32(int32x4_t a);           //
float32x4_t vreinterpretq_f32_s32(int32x4_t a);         //
uint8x16_t vreinterpretq_u8_s32(int32x4_t a);           //
uint16x8_t vreinterpretq_u16_s32(int32x4_t a);          //
uint32x4_t vreinterpretq_u32_s32(int32x4_t a);          //
poly8x16_t vreinterpretq_p8_s32(int32x4_t a);           //
poly16x8_t vreinterpretq_p16_s32(int32x4_t a);          //
uint64x2_t vreinterpretq_u64_s32(int32x4_t a);          //
int64x2_t vreinterpretq_s64_s32(int32x4_t a);           //
float64x2_t vreinterpretq_f64_s32(int32x4_t a);         //
poly64x2_t vreinterpretq_p64_s32(int32x4_t a);          //
poly128_t vreinterpretq_p128_s32(int32x4_t a);          //
float16x8_t vreinterpretq_f16_s32(int32x4_t a);         //
int8x16_t vreinterpretq_s8_f32(float32x4_t a);          //
int16x8_t vreinterpretq_s16_f32(float32x4_t a);         //
int32x4_t vreinterpretq_s32_f32(float32x4_t a);         //
uint8x16_t vreinterpretq_u8_f32(float32x4_t a);         //
uint16x8_t vreinterpretq_u16_f32(float32x4_t a);        //
uint32x4_t vreinterpretq_u32_f32(float32x4_t a);        //
poly8x16_t vreinterpretq_p8_f32(float32x4_t a);         //
poly16x8_t vreinterpretq_p16_f32(float32x4_t a);        //
uint64x2_t vreinterpretq_u64_f32(float32x4_t a);        //
int64x2_t vreinterpretq_s64_f32(float32x4_t a);         //
float64x2_t vreinterpretq_f64_f32(float32x4_t a);       //
poly64x2_t vreinterpretq_p64_f32(float32x4_t a);        //
poly128_t vreinterpretq_p128_f32(float32x4_t a);        //
poly64x2_t vreinterpretq_p64_f64(float64x2_t a);        //
poly128_t vreinterpretq_p128_f64(float64x2_t a);        //
float16x8_t vreinterpretq_f16_f32(float32x4_t a);       //
int8x16_t vreinterpretq_s8_u8(uint8x16_t a);            //
int16x8_t vreinterpretq_s16_u8(uint8x16_t a);           //
int32x4_t vreinterpretq_s32_u8(uint8x16_t a);           //
float32x4_t vreinterpretq_f32_u8(uint8x16_t a);         //
uint16x8_t vreinterpretq_u16_u8(uint8x16_t a);          //
uint32x4_t vreinterpretq_u32_u8(uint8x16_t a);          //
poly8x16_t vreinterpretq_p8_u8(uint8x16_t a);           //
poly16x8_t vreinterpretq_p16_u8(uint8x16_t a);          //
uint64x2_t vreinterpretq_u64_u8(uint8x16_t a);          //
int64x2_t vreinterpretq_s64_u8(uint8x16_t a);           //
float64x2_t vreinterpretq_f64_u8(uint8x16_t a);         //
poly64x2_t vreinterpretq_p64_u8(uint8x16_t a);          //
poly128_t vreinterpretq_p128_u8(uint8x16_t a);          //
float16x8_t vreinterpretq_f16_u8(uint8x16_t a);         //
int8x16_t vreinterpretq_s8_u16(uint16x8_t a);           //
int16x8_t vreinterpretq_s16_u16(uint16x8_t a);          //
int32x4_t vreinterpretq_s32_u16(uint16x8_t a);          //
float32x4_t vreinterpretq_f32_u16(uint16x8_t a);        //
uint8x16_t vreinterpretq_u8_u16(uint16x8_t a);          //
uint32x4_t vreinterpretq_u32_u16(uint16x8_t a);         //
poly8x16_t vreinterpretq_p8_u16(uint16x8_t a);          //
poly16x8_t vreinterpretq_p16_u16(uint16x8_t a);         //
uint64x2_t vreinterpretq_u64_u16(uint16x8_t a);         //
int64x2_t vreinterpretq_s64_u16(uint16x8_t a);          //
float64x2_t vreinterpretq_f64_u16(uint16x8_t a);        //
poly64x2_t vreinterpretq_p64_u16(uint16x8_t a);         //
poly128_t vreinterpretq_p128_u16(uint16x8_t a);         //
float16x8_t vreinterpretq_f16_u16(uint16x8_t a);        //
int8x16_t vreinterpretq_s8_u32(uint32x4_t a);           //
int16x8_t vreinterpretq_s16_u32(uint32x4_t a);          //
int32x4_t vreinterpretq_s32_u32(uint32x4_t a);          //
float32x4_t vreinterpretq_f32_u32(uint32x4_t a);        //
uint8x16_t vreinterpretq_u8_u32(uint32x4_t a);          //
uint16x8_t vreinterpretq_u16_u32(uint32x4_t a);         //
poly8x16_t vreinterpretq_p8_u32(uint32x4_t a);          //
poly16x8_t vreinterpretq_p16_u32(uint32x4_t a);         //
uint64x2_t vreinterpretq_u64_u32(uint32x4_t a);         //
int64x2_t vreinterpretq_s64_u32(uint32x4_t a);          //
float64x2_t vreinterpretq_f64_u32(uint32x4_t a);        //
poly64x2_t vreinterpretq_p64_u32(uint32x4_t a);         //
poly128_t vreinterpretq_p128_u32(uint32x4_t a);         //
float16x8_t vreinterpretq_f16_u32(uint32x4_t a);        //
int8x16_t vreinterpretq_s8_p8(poly8x16_t a);            //
int16x8_t vreinterpretq_s16_p8(poly8x16_t a);           //
int32x4_t vreinterpretq_s32_p8(poly8x16_t a);           //
float32x4_t vreinterpretq_f32_p8(poly8x16_t a);         //
uint8x16_t vreinterpretq_u8_p8(poly8x16_t a);           //
uint16x8_t vreinterpretq_u16_p8(poly8x16_t a);          //
uint32x4_t vreinterpretq_u32_p8(poly8x16_t a);          //
poly16x8_t vreinterpretq_p16_p8(poly8x16_t a);          //
uint64x2_t vreinterpretq_u64_p8(poly8x16_t a);          //
int64x2_t vreinterpretq_s64_p8(poly8x16_t a);           //
float64x2_t vreinterpretq_f64_p8(poly8x16_t a);         //
poly64x2_t vreinterpretq_p64_p8(poly8x16_t a);          //
poly128_t vreinterpretq_p128_p8(poly8x16_t a);          //
float16x8_t vreinterpretq_f16_p8(poly8x16_t a);         //
int8x16_t vreinterpretq_s8_p16(poly16x8_t a);           //
int16x8_t vreinterpretq_s16_p16(poly16x8_t a);          //
int32x4_t vreinterpretq_s32_p16(poly16x8_t a);          //
float32x4_t vreinterpretq_f32_p16(poly16x8_t a);        //
uint8x16_t vreinterpretq_u8_p16(poly16x8_t a);          //
uint16x8_t vreinterpretq_u16_p16(poly16x8_t a);         //
uint32x4_t vreinterpretq_u32_p16(poly16x8_t a);         //
poly8x16_t vreinterpretq_p8_p16(poly16x8_t a);          //
uint64x2_t vreinterpretq_u64_p16(poly16x8_t a);         //
int64x2_t vreinterpretq_s64_p16(poly16x8_t a);          //
float64x2_t vreinterpretq_f64_p16(poly16x8_t a);        //
poly64x2_t vreinterpretq_p64_p16(poly16x8_t a);         //
poly128_t vreinterpretq_p128_p16(poly16x8_t a);         //
float16x8_t vreinterpretq_f16_p16(poly16x8_t a);        //
int8x16_t vreinterpretq_s8_u64(uint64x2_t a);           //
int16x8_t vreinterpretq_s16_u64(uint64x2_t a);          //
int32x4_t vreinterpretq_s32_u64(uint64x2_t a);          //
float32x4_t vreinterpretq_f32_u64(uint64x2_t a);        //
uint8x16_t vreinterpretq_u8_u64(uint64x2_t a);          //
uint16x8_t vreinterpretq_u16_u64(uint64x2_t a);         //
uint32x4_t vreinterpretq_u32_u64(uint64x2_t a);         //
poly8x16_t vreinterpretq_p8_u64(uint64x2_t a);          //
poly16x8_t vreinterpretq_p16_u64(uint64x2_t a);         //
int64x2_t vreinterpretq_s64_u64(uint64x2_t a);          //
float64x2_t vreinterpretq_f64_u64(uint64x2_t a);        //
float64x2_t vreinterpretq_f64_s64(int64x2_t a);         //
poly64x2_t vreinterpretq_p64_s64(int64x2_t a);          //
poly128_t vreinterpretq_p128_s64(int64x2_t a);          //
poly64x2_t vreinterpretq_p64_u64(uint64x2_t a);         //
poly128_t vreinterpretq_p128_u64(uint64x2_t a);         //
float16x8_t vreinterpretq_f16_u64(uint64x2_t a);        //
int8x16_t vreinterpretq_s8_s64(int64x2_t a);            //
int16x8_t vreinterpretq_s16_s64(int64x2_t a);           //
int32x4_t vreinterpretq_s32_s64(int64x2_t a);           //
float32x4_t vreinterpretq_f32_s64(int64x2_t a);         //
uint8x16_t vreinterpretq_u8_s64(int64x2_t a);           //
uint16x8_t vreinterpretq_u16_s64(int64x2_t a);          //
uint32x4_t vreinterpretq_u32_s64(int64x2_t a);          //
poly8x16_t vreinterpretq_p8_s64(int64x2_t a);           //
poly16x8_t vreinterpretq_p16_s64(int64x2_t a);          //
uint64x2_t vreinterpretq_u64_s64(int64x2_t a);          //
uint64x2_t vreinterpretq_u64_p64(poly64x2_t a);         //
float16x8_t vreinterpretq_f16_s64(int64x2_t a);         //
int8x16_t vreinterpretq_s8_f16(float16x8_t a);          //
int16x8_t vreinterpretq_s16_f16(float16x8_t a);         //
int32x4_t vreinterpretq_s32_f16(float16x8_t a);         //
float32x4_t vreinterpretq_f32_f16(float16x8_t a);       //
uint8x16_t vreinterpretq_u8_f16(float16x8_t a);         //
uint16x8_t vreinterpretq_u16_f16(float16x8_t a);        //
uint32x4_t vreinterpretq_u32_f16(float16x8_t a);        //
poly8x16_t vreinterpretq_p8_f16(float16x8_t a);         //
poly16x8_t vreinterpretq_p16_f16(float16x8_t a);        //
uint64x2_t vreinterpretq_u64_f16(float16x8_t a);        //
int64x2_t vreinterpretq_s64_f16(float16x8_t a);         //
float64x2_t vreinterpretq_f64_f16(float16x8_t a);       //
poly64x2_t vreinterpretq_p64_f16(float16x8_t a);        //
poly128_t vreinterpretq_p128_f16(float16x8_t a);        //
int8x8_t vreinterpret_s8_f64(float64x1_t a);            //
int16x4_t vreinterpret_s16_f64(float64x1_t a);          //
int32x2_t vreinterpret_s32_f64(float64x1_t a);          //
uint8x8_t vreinterpret_u8_f64(float64x1_t a);           //
uint16x4_t vreinterpret_u16_f64(float64x1_t a);         //
uint32x2_t vreinterpret_u32_f64(float64x1_t a);         //
poly8x8_t vreinterpret_p8_f64(float64x1_t a);           //
poly16x4_t vreinterpret_p16_f64(float64x1_t a);         //
uint64x1_t vreinterpret_u64_f64(float64x1_t a);         //
int64x1_t vreinterpret_s64_f64(float64x1_t a);          //
float16x4_t vreinterpret_f16_f64(float64x1_t a);        //
float32x2_t vreinterpret_f32_f64(float64x1_t a);        //
int8x16_t vreinterpretq_s8_f64(float64x2_t a);          //
int16x8_t vreinterpretq_s16_f64(float64x2_t a);         //
int32x4_t vreinterpretq_s32_f64(float64x2_t a);         //
uint8x16_t vreinterpretq_u8_f64(float64x2_t a);         //
uint16x8_t vreinterpretq_u16_f64(float64x2_t a);        //
uint32x4_t vreinterpretq_u32_f64(float64x2_t a);        //
poly8x16_t vreinterpretq_p8_f64(float64x2_t a);         //
poly16x8_t vreinterpretq_p16_f64(float64x2_t a);        //
uint64x2_t vreinterpretq_u64_f64(float64x2_t a);        //
int64x2_t vreinterpretq_s64_f64(float64x2_t a);         //
float16x8_t vreinterpretq_f16_f64(float64x2_t a);       //
float32x4_t vreinterpretq_f32_f64(float64x2_t a);       //
int8x8_t vreinterpret_s8_p64(poly64x1_t a);             //
int16x4_t vreinterpret_s16_p64(poly64x1_t a);           //
int32x2_t vreinterpret_s32_p64(poly64x1_t a);           //
uint8x8_t vreinterpret_u8_p64(poly64x1_t a);            //
uint16x4_t vreinterpret_u16_p64(poly64x1_t a);          //
uint32x2_t vreinterpret_u32_p64(poly64x1_t a);          //
poly8x8_t vreinterpret_p8_p64(poly64x1_t a);            //
poly16x4_t vreinterpret_p16_p64(poly64x1_t a);          //
int64x1_t vreinterpret_s64_p64(poly64x1_t a);           //
float64x1_t vreinterpret_f64_p64(poly64x1_t a);         //
float16x4_t vreinterpret_f16_p64(poly64x1_t a);         //
int8x16_t vreinterpretq_s8_p64(poly64x2_t a);           //
int16x8_t vreinterpretq_s16_p64(poly64x2_t a);          //
int32x4_t vreinterpretq_s32_p64(poly64x2_t a);          //
uint8x16_t vreinterpretq_u8_p64(poly64x2_t a);          //
uint16x8_t vreinterpretq_u16_p64(poly64x2_t a);         //
uint32x4_t vreinterpretq_u32_p64(poly64x2_t a);         //
poly8x16_t vreinterpretq_p8_p64(poly64x2_t a);          //
poly16x8_t vreinterpretq_p16_p64(poly64x2_t a);         //
int64x2_t vreinterpretq_s64_p64(poly64x2_t a);          //
float64x2_t vreinterpretq_f64_p64(poly64x2_t a);        //
float16x8_t vreinterpretq_f16_p64(poly64x2_t a);        //
int8x16_t vreinterpretq_s8_p128(poly128_t a);           //
int16x8_t vreinterpretq_s16_p128(poly128_t a);          //
int32x4_t vreinterpretq_s32_p128(poly128_t a);          //
uint8x16_t vreinterpretq_u8_p128(poly128_t a);          //
uint16x8_t vreinterpretq_u16_p128(poly128_t a);         //
uint32x4_t vreinterpretq_u32_p128(poly128_t a);         //
poly8x16_t vreinterpretq_p8_p128(poly128_t a);          //
poly16x8_t vreinterpretq_p16_p128(poly128_t a);         //
uint64x2_t vreinterpretq_u64_p128(poly128_t a);         //
int64x2_t vreinterpretq_s64_p128(poly128_t a);          //
float64x2_t vreinterpretq_f64_p128(poly128_t a);        //
float16x8_t vreinterpretq_f16_p128(poly128_t a);        //
poly128_t vldrq_p128(poly128_t const* ptr);             // LDR Qd,[Xn]
void vstrq_p128(poly128_t* ptr, poly128_t val);         // STR Qt,[Xn]
uint8x16_t vaeseq_u8(uint8x16_t data, uint8x16_t key);  // AESE Vd.16B,Vn.16B
uint8x16_t vaesdq_u8(uint8x16_t data, uint8x16_t key);  // AESD Vd.16B,Vn.16B
uint8x16_t vaesmcq_u8(uint8x16_t data);                 // AESMC Vd.16B,Vn.16B
uint8x16_t vaesimcq_u8(uint8x16_t data);                // AESIMC Vd.16B,Vn.16B
uint32x4_t vsha1cq_u32(uint32x4_t hash_abcd, uint32_t hash_e, uint32x4_t wk);  // SHA1C Qd,Sn,Vm.4S
uint32x4_t vsha1pq_u32(uint32x4_t hash_abcd, uint32_t hash_e, uint32x4_t wk);  // SHA1P Qd,Sn,Vm.4S
uint32x4_t vsha1mq_u32(uint32x4_t hash_abcd, uint32_t hash_e, uint32x4_t wk);  // SHA1M Qd,Sn,Vm.4S
uint32_t vsha1h_u32(uint32_t hash_e);                                          // SHA1H Sd,Sn
uint32x4_t vsha1su0q_u32(
    uint32x4_t w0_3, uint32x4_t w4_7, uint32x4_t w8_11);        // SHA1SU0 Vd.4S,Vn.4S,Vm.4S
uint32x4_t vsha1su1q_u32(uint32x4_t tw0_3, uint32x4_t w12_15);  // SHA1SU1 Vd.4S,Vn.4S
uint32x4_t vsha256hq_u32(
    uint32x4_t hash_abcd, uint32x4_t hash_efgh, uint32x4_t wk);  // SHA256H Qd,Qn,Vm.4S
uint32x4_t vsha256h2q_u32(
    uint32x4_t hash_efgh, uint32x4_t hash_abcd, uint32x4_t wk);  // SHA256H2 Qd,Qn,Vm.4S
uint32x4_t vsha256su0q_u32(uint32x4_t w0_3, uint32x4_t w4_7);    // SHA256SU0 Vd.4S,Vn.4S
uint32x4_t vsha256su1q_u32(
    uint32x4_t tw0_3, uint32x4_t w8_11, uint32x4_t w12_15);      // SHA256SU1 Vd.4S,Vn.4S,Vm.4S
poly128_t vmull_p64(poly64_t a, poly64_t b);                     // PMULL Vd.1Q,Vn.1D,Vm.1D
poly128_t vmull_high_p64(poly64x2_t a, poly64x2_t b);            // PMULL2 Vd.1Q,Vn.2D,Vm.2D
poly8x8_t vadd_p8(poly8x8_t a, poly8x8_t b);                     // EOR Vd.8B,Vn.8B,Vm.8B
poly16x4_t vadd_p16(poly16x4_t a, poly16x4_t b);                 // EOR Vd.8B,Vn.8B,Vm.8B
poly64x1_t vadd_p64(poly64x1_t a, poly64x1_t b);                 // EOR Vd.8B,Vn.8B,Vm.8B
poly8x16_t vaddq_p8(poly8x16_t a, poly8x16_t b);                 // EOR Vd.16B,Vn.16B,Vm.16B
poly16x8_t vaddq_p16(poly16x8_t a, poly16x8_t b);                // EOR Vd.16B,Vn.16B,Vm.16B
poly64x2_t vaddq_p64(poly64x2_t a, poly64x2_t b);                // EOR Vd.16B,Vn.16B,Vm.16B
poly128_t vaddq_p128(poly128_t a, poly128_t b);                  // EOR Vd.16B,Vn.16B,Vm.16B
uint32_t __crc32b(uint32_t a, uint8_t b);                        // CRC32B Wd,Wn,Wm
uint32_t __crc32h(uint32_t a, uint16_t b);                       // CRC32H Wd,Wn,Wm
uint32_t __crc32w(uint32_t a, uint32_t b);                       // CRC32W Wd,Wn,Wm
uint32_t __crc32d(uint32_t a, uint64_t b);                       // CRC32X Wd,Wn,Xm
uint32_t __crc32cb(uint32_t a, uint8_t b);                       // CRC32CB Wd,Wn,Wm
uint32_t __crc32ch(uint32_t a, uint16_t b);                      // CRC32CH Wd,Wn,Wm
uint32_t __crc32cw(uint32_t a, uint32_t b);                      // CRC32CW Wd,Wn,Wm
uint32_t __crc32cd(uint32_t a, uint64_t b);                      // CRC32CX Wd,Wn,Xm
int16x4_t vqrdmlah_s16(int16x4_t a, int16x4_t b, int16x4_t c);   // SQRDMLAH Vd.4H,Vn.4H,Vm.4H
int32x2_t vqrdmlah_s32(int32x2_t a, int32x2_t b, int32x2_t c);   // SQRDMLAH Vd.2S,Vn.2S,Vm.2S
int16x8_t vqrdmlahq_s16(int16x8_t a, int16x8_t b, int16x8_t c);  // SQRDMLAH Vd.8H,Vn.8H,Vm.8H
int32x4_t vqrdmlahq_s32(int32x4_t a, int32x4_t b, int32x4_t c);  // SQRDMLAH Vd.4S,Vn.4S,Vm.4S
int16x4_t vqrdmlsh_s16(int16x4_t a, int16x4_t b, int16x4_t c);   // SQRDMLSH Vd.4H,Vn.4H,Vm.4H
int32x2_t vqrdmlsh_s32(int32x2_t a, int32x2_t b, int32x2_t c);   // SQRDMLSH Vd.2S,Vn.2S,Vm.2S
int16x8_t vqrdmlshq_s16(int16x8_t a, int16x8_t b, int16x8_t c);  // SQRDMLSH Vd.8H,Vn.8H,Vm.8H
int32x4_t vqrdmlshq_s32(int32x4_t a, int32x4_t b, int32x4_t c);  // SQRDMLSH Vd.4S,Vn.4S,Vm.4S
int16x4_t vqrdmlah_lane_s16(
    int16x4_t a, int16x4_t b, int16x4_t v, const int lane);  // SQRDMLAH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqrdmlahq_lane_s16(
    int16x8_t a, int16x8_t b, int16x4_t v, const int lane);  // SQRDMLAH Vd.8H,Vn.8H,Vm.H[lane]
int16x4_t vqrdmlah_laneq_s16(
    int16x4_t a, int16x4_t b, int16x8_t v, const int lane);  // SQRDMLAH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqrdmlahq_laneq_s16(
    int16x8_t a, int16x8_t b, int16x8_t v, const int lane);  // SQRDMLAH Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vqrdmlah_lane_s32(
    int32x2_t a, int32x2_t b, int32x2_t v, const int lane);  // SQRDMLAH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqrdmlahq_lane_s32(
    int32x4_t a, int32x4_t b, int32x2_t v, const int lane);  // SQRDMLAH Vd.4S,Vn.4S,Vm.S[lane]
int32x2_t vqrdmlah_laneq_s32(
    int32x2_t a, int32x2_t b, int32x4_t v, const int lane);  // SQRDMLAH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqrdmlahq_laneq_s32(
    int32x4_t a, int32x4_t b, int32x4_t v, const int lane);  // SQRDMLAH Vd.4S,Vn.4S,Vm.S[lane]
int16x4_t vqrdmlsh_lane_s16(
    int16x4_t a, int16x4_t b, int16x4_t v, const int lane);  // SQRDMLSH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqrdmlshq_lane_s16(
    int16x8_t a, int16x8_t b, int16x4_t v, const int lane);  // SQRDMLSH Vd.8H,Vn.8H,Vm.H[lane]
int16x4_t vqrdmlsh_laneq_s16(
    int16x4_t a, int16x4_t b, int16x8_t v, const int lane);  // SQRDMLSH Vd.4H,Vn.4H,Vm.H[lane]
int16x8_t vqrdmlshq_laneq_s16(
    int16x8_t a, int16x8_t b, int16x8_t v, const int lane);  // SQRDMLSH Vd.8H,Vn.8H,Vm.H[lane]
int32x2_t vqrdmlsh_lane_s32(
    int32x2_t a, int32x2_t b, int32x2_t v, const int lane);  // SQRDMLSH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqrdmlshq_lane_s32(
    int32x4_t a, int32x4_t b, int32x2_t v, const int lane);  // SQRDMLSH Vd.4S,Vn.4S,Vm.S[lane]
int32x2_t vqrdmlsh_laneq_s32(
    int32x2_t a, int32x2_t b, int32x4_t v, const int lane);  // SQRDMLSH Vd.2S,Vn.2S,Vm.S[lane]
int32x4_t vqrdmlshq_laneq_s32(
    int32x4_t a, int32x4_t b, int32x4_t v, const int lane);  // SQRDMLSH Vd.4S,Vn.4S,Vm.S[lane]
int16_t vqrdmlahh_s16(int16_t a, int16_t b, int16_t c);      // SQRDMLSH Hd,Hn,Hm
int32_t vqrdmlahs_s32(int32_t a, int32_t b, int32_t c);      // SQRDMLSH Sd,Sn,Sm
int16_t vqrdmlshh_s16(int16_t a, int16_t b, int16_t c);      // SQRDMLSH Hd,Hn,Hm
int32_t vqrdmlshs_s32(int32_t a, int32_t b, int32_t c);      // SQRDMLSH Sd,Sn,Sm
int16_t vqrdmlahh_lane_s16(
    int16_t a, int16_t b, int16x4_t v, const int lane);  // SQRDMLAH Hd,Hn,Vm.H[lane]
int16_t vqrdmlahh_laneq_s16(
    int16_t a, int16_t b, int16x8_t v, const int lane);  // SQRDMLAH Hd,Hn,Vm.H[lane]
int32_t vqrdmlahs_lane_s32(
    int32_t a, int32_t b, int32x2_t v, const int lane);  // SQRDMLAH Sd,Sn,Vm.S[lane]
int32_t vqrdmlahs_laneq_s32(
    int32_t a, int32_t b, int32x4_t v, const int lane);  // SQRDMLAH Sd,Sn,Vm.S[lane]
int16_t vqrdmlshh_lane_s16(
    int16_t a, int16_t b, int16x4_t v, const int lane);  // SQRDMLSH Hd,Hn,Vm.H[lane]
int16_t vqrdmlshh_laneq_s16(
    int16_t a, int16_t b, int16x8_t v, const int lane);  // SQRDMLSH Hd,Hn,Vm.H[lane]
int32_t vqrdmlshs_lane_s32(
    int32_t a, int32_t b, int32x2_t v, const int lane);  // SQRDMLSH Sd,Sn,Vm.S[lane]
int32_t vqrdmlshs_laneq_s32(
    int32_t a, int32_t b, int32x4_t v, const int lane);              // SQRDMLSH Sd,Sn,Vm.S[lane]
float16_t vabsh_f16(float16_t a);                                    // FABS Hd,Hn
uint16_t vceqzh_f16(float16_t a);                                    // FCMEQ Hd,Hn,#0
uint16_t vcgezh_f16(float16_t a);                                    // FCMGE Hd,Hn,#0
uint16_t vcgtzh_f16(float16_t a);                                    // FCMGT Hd,Hn,#0
uint16_t vclezh_f16(float16_t a);                                    // FCMLE Hd,Hn,#0
uint16_t vcltzh_f16(float16_t a);                                    // FCMLT Hd,Hn,#0
float16_t vcvth_f16_u16(uint16_t a);                                 // UCVTF Hd,Hn
float16_t vcvth_f16_u32(uint32_t a);                                 // UCVTF Hd,Hn
float16_t vcvth_f16_u64(uint64_t a);                                 // UCVTF Hd,Hn
int16_t vcvth_s16_f16(float16_t a);                                  // FCVTZS Hd,Hn
int32_t vcvth_s32_f16(float16_t a);                                  // FCVTZS Hd,Hn
int64_t vcvth_s64_f16(float16_t a);                                  // FCVTZS Hd,Hn
uint16_t vcvth_u16_f16(float16_t a);                                 // FCVTZU Hd,Hn
uint32_t vcvth_u32_f16(float16_t a);                                 // FCVTZU Hd,Hn
uint64_t vcvth_u64_f16(float16_t a);                                 // FCVTZU Hd,Hn
int16_t vcvtah_s16_f16(float16_t a);                                 // FCVTAS Hd,Hn
int32_t vcvtah_s32_f16(float16_t a);                                 // FCVTAS Hd,Hn
int64_t vcvtah_s64_f16(float16_t a);                                 // FCVTAS Hd,Hn
uint16_t vcvtah_u16_f16(float16_t a);                                // FCVTAU Hd,Hn
uint32_t vcvtah_u32_f16(float16_t a);                                // FCVTAU Hd,Hn
uint64_t vcvtah_u64_f16(float16_t a);                                // FCVTAU Hd,Hn
int16_t vcvtmh_s16_f16(float16_t a);                                 // FCVTMS Hd,Hn
int32_t vcvtmh_s32_f16(float16_t a);                                 // FCVTMS Hd,Hn
int64_t vcvtmh_s64_f16(float16_t a);                                 // FCVTMS Hd,Hn
uint16_t vcvtmh_u16_f16(float16_t a);                                // FCVTMU Hd,Hn
uint32_t vcvtmh_u32_f16(float16_t a);                                // FCVTMU Hd,Hn
uint64_t vcvtmh_u64_f16(float16_t a);                                // FCVTMU Hd,Hn
int16_t vcvtnh_s16_f16(float16_t a);                                 // FCVTNS Hd,Hn
int32_t vcvtnh_s32_f16(float16_t a);                                 // FCVTNS Hd,Hn
int64_t vcvtnh_s64_f16(float16_t a);                                 // FCVTNS Hd,Hn
uint16_t vcvtnh_u16_f16(float16_t a);                                // FCVTNU Hd,Hn
uint32_t vcvtnh_u32_f16(float16_t a);                                // FCVTNU Hd,Hn
uint64_t vcvtnh_u64_f16(float16_t a);                                // FCVTNU Hd,Hn
int16_t vcvtph_s16_f16(float16_t a);                                 // FCVTPS Hd,Hn
int32_t vcvtph_s32_f16(float16_t a);                                 // FCVTPS Hd,Hn
int64_t vcvtph_s64_f16(float16_t a);                                 // FCVTPS Hd,Hn
uint16_t vcvtph_u16_f16(float16_t a);                                // FCVTPU Hd,Hn
uint32_t vcvtph_u32_f16(float16_t a);                                // FCVTPU Hd,Hn
uint64_t vcvtph_u64_f16(float16_t a);                                // FCVTPU Hd,Hn
float16_t vnegh_f16(float16_t a);                                    // FNEG Hd,Hn
float16_t vrecpeh_f16(float16_t a);                                  // FRECPE Hd,Hn
float16_t vrecpxh_f16(float16_t a);                                  // FRECPX Hd,Hn
float16_t vrndh_f16(float16_t a);                                    // FRINTZ Hd,Hn
float16_t vrndah_f16(float16_t a);                                   // FRINTA Hd,Hn
float16_t vrndih_f16(float16_t a);                                   // FRINTI Hd,Hn
float16_t vrndmh_f16(float16_t a);                                   // FRINTM Hd,Hn
float16_t vrndnh_f16(float16_t a);                                   // FRINTN Hd,Hn
float16_t vrndph_f16(float16_t a);                                   // FRINTP Hd,Hn
float16_t vrndxh_f16(float16_t a);                                   // FRINTX Hd,Hn
float16_t vrsqrteh_f16(float16_t a);                                 // FRSQRTE Hd,Hn
float16_t vsqrth_f16(float16_t a);                                   // FSQRT Hd,Hn
float16_t vaddh_f16(float16_t a, float16_t b);                       // FADD Hd,Hn,Hm
float16_t vabdh_f16(float16_t a, float16_t b);                       // FABD Hd,Hn,Hm
uint16_t vcageh_f16(float16_t a, float16_t b);                       // FACGE Hd,Hn,Hm
uint16_t vcagth_f16(float16_t a, float16_t b);                       // FACGT Hd,Hn,Hm
uint16_t vcaleh_f16(float16_t a, float16_t b);                       // FACGE Hd,Hn,Hm
uint16_t vcalth_f16(float16_t a, float16_t b);                       // FACGT Hd,Hn,Hm
uint16_t vceqh_f16(float16_t a, float16_t b);                        // FCMEQ Hd,Hn,Hm
uint16_t vcgeh_f16(float16_t a, float16_t b);                        // FCMGE Hd,Hn,Hm
uint16_t vcgth_f16(float16_t a, float16_t b);                        // FCMGT Hd,Hn,Hm
uint16_t vcleh_f16(float16_t a, float16_t b);                        // FCMGE Hd,Hn,Hm
uint16_t vclth_f16(float16_t a, float16_t b);                        // FCMGT Hd,Hn,Hm
float16_t vcvth_n_f16_s16(int16_t a, const int n);                   // SCVTF Hd,Hn,#n
float16_t vcvth_n_f16_s32(int32_t a, const int n);                   // SCVTF Hd,Hn,#n
float16_t vcvth_n_f16_s64(int64_t a, const int n);                   // SCVTF Hd,Hn,#n
float16_t vcvth_n_f16_u16(uint16_t a, const int n);                  // UCVTF Hd,Hn,#n
float16_t vcvth_n_f16_u32(uint32_t a, const int n);                  // UCVTF Hd,Hn,#n
float16_t vcvth_n_f16_u64(uint64_t a, const int n);                  // UCVTF Hd,Hn,#n
int16_t vcvth_n_s16_f16(float16_t a, const int n);                   // FCVTZS Hd,Hn,#n
int32_t vcvth_n_s32_f16(float16_t a, const int n);                   // FCVTZS Hd,Hn,#n
int64_t vcvth_n_s64_f16(float16_t a, const int n);                   // FCVTZS Hd,Hn,#n
uint16_t vcvth_n_u16_f16(float16_t a, const int n);                  // FCVTZU Hd,Hn,#n
uint32_t vcvth_n_u32_f16(float16_t a, const int n);                  // FCVTZU Hd,Hn,#n
uint64_t vcvth_n_u64_f16(float16_t a, const int n);                  // FCVTZU Hd,Hn,#n
float16_t vdivh_f16(float16_t a, float16_t b);                       // FDIV Hd,Hn,Hm
float16_t vmaxh_f16(float16_t a, float16_t b);                       // FMAX Hd,Hn,Hm
float16_t vmaxnmh_f16(float16_t a, float16_t b);                     // FMAXNM Hd,Hn,Hm
float16_t vminh_f16(float16_t a, float16_t b);                       // FMIN Hd,Hn,Hm
float16_t vminnmh_f16(float16_t a, float16_t b);                     // FMINNM Hd,Hn,Hm
float16_t vmulh_f16(float16_t a, float16_t b);                       // FMUL Hd,Hn,Hm
float16_t vmulxh_f16(float16_t a, float16_t b);                      // FMULX Hd,Hn,Hm
float16_t vrecpsh_f16(float16_t a, float16_t b);                     // FRECPS Hd,Hn,Hm
float16_t vrsqrtsh_f16(float16_t a, float16_t b);                    // FRSQRTS Hd,Hn,Hm
float16_t vsubh_f16(float16_t a, float16_t b);                       // FSUB Hd,Hn,Hm
float16_t vfmah_f16(float16_t a, float16_t b, float16_t c);          // FMADD Hd,Hn,Hm,Ha
float16_t vfmsh_f16(float16_t a, float16_t b, float16_t c);          // FMSUB Hd,Hn,Hm,Ha
float16x4_t vabs_f16(float16x4_t a);                                 // FABS Vd.4H,Vn.4H
float16x8_t vabsq_f16(float16x8_t a);                                // FABS Vd.8H,Vn.8H
uint16x4_t vceqz_f16(float16x4_t a);                                 // FCMEQ Vd.4H,Vn.4H,#0
uint16x8_t vceqzq_f16(float16x8_t a);                                // FCMEQ Vd.8H,Vn.8H,#0
uint16x4_t vcgez_f16(float16x4_t a);                                 // FCMGE Vd.4H,Vn.4H,#0
uint16x8_t vcgezq_f16(float16x8_t a);                                // FCMGE Vd.8H,Vn.8H,#0
uint16x4_t vcgtz_f16(float16x4_t a);                                 // FCMGT Vd.4H,Vn.4H,#0
uint16x8_t vcgtzq_f16(float16x8_t a);                                // FCMGT Vd.8H,Vn.8H,#0
uint16x4_t vclez_f16(float16x4_t a);                                 // FCMLE Vd.4H,Vn.4H,#0
uint16x8_t vclezq_f16(float16x8_t a);                                // FCMLE Vd.8H,Vn.8H,#0
uint16x4_t vcltz_f16(float16x4_t a);                                 // FCMLT Vd.4H,Vn.4H,#0
uint16x8_t vcltzq_f16(float16x8_t a);                                // FCMLT Vd.8H,Vn.8H,#0
float16x4_t vcvt_f16_s16(int16x4_t a);                               // SCVTF Vd.4H,Vn.4H,#0
float16x8_t vcvtq_f16_s16(int16x8_t a);                              // SCVTF Vd.8H,Vn.8H,#0
float16x4_t vcvt_f16_u16(uint16x4_t a);                              // UCVTF Vd.4H,Vn.4H,#0
float16x8_t vcvtq_f16_u16(uint16x8_t a);                             // UCVTF Vd.8H,Vn.8H
int16x4_t vcvt_s16_f16(float16x4_t a);                               // FCVTZS Vd.4H,Vn.4H
int16x8_t vcvtq_s16_f16(float16x8_t a);                              // FCVTZS Vd.8H,Vn.8H
uint16x4_t vcvt_u16_f16(float16x4_t a);                              // FCVTZS Vd.4H,Vn.4H
uint16x8_t vcvtq_u16_f16(float16x8_t a);                             // FCVTZS Vd.8H,Vn.8H
int16x4_t vcvta_s16_f16(float16x4_t a);                              // FCVTAS Vd.4H,Vn.4H
int16x8_t vcvtaq_s16_f16(float16x8_t a);                             // FCVTAS Vd.8H,Vn.8H
uint16x4_t vcvta_u16_f16(float16x4_t a);                             // FCVTAU Vd.4H,Vn.4H
uint16x8_t vcvtaq_u16_f16(float16x8_t a);                            // FCVTAU Vd.8H,Vn.8H
int16x4_t vcvtm_s16_f16(float16x4_t a);                              // FCVTMS Vd.4H,Vn.4H
int16x8_t vcvtmq_s16_f16(float16x8_t a);                             // FCVTMS Vd.8H,Vn.8H
uint16x4_t vcvtm_u16_f16(float16x4_t a);                             // FCVTMU Vd.4H,Vn.4H
uint16x8_t vcvtmq_u16_f16(float16x8_t a);                            // FCVTMU Vd.8H,Vn.8H
int16x4_t vcvtn_s16_f16(float16x4_t a);                              // FCVTNS Vd.4H,Vn.4H
int16x8_t vcvtnq_s16_f16(float16x8_t a);                             // FCVTNS Vd.8H,Vn.8H
uint16x4_t vcvtn_u16_f16(float16x4_t a);                             // FCVTNU Vd.4H,Vn.4H
uint16x8_t vcvtnq_u16_f16(float16x8_t a);                            // FCVTNU Vd.8H,Vn.8H
int16x4_t vcvtp_s16_f16(float16x4_t a);                              // FCVTPS Vd.4H,Vn.4H
int16x8_t vcvtpq_s16_f16(float16x8_t a);                             // FCVTPS Vd.8H,Vn.8H
uint16x4_t vcvtp_u16_f16(float16x4_t a);                             // FCVTPU Vd.4H,Vn.4H
uint16x8_t vcvtpq_u16_f16(float16x8_t a);                            // FCVTPU Vd.8H,Vn.8H
float16x4_t vneg_f16(float16x4_t a);                                 // FNEG Vd.4H,Vn.4H
float16x8_t vnegq_f16(float16x8_t a);                                // FNEG Vd.8H,Vn.8H
float16x4_t vrecpe_f16(float16x4_t a);                               // FRECPE Vd.4H,Vn.4H
float16x8_t vrecpeq_f16(float16x8_t a);                              // FRECPE Vd.8H,Vn.8H
float16x4_t vrnd_f16(float16x4_t a);                                 // FRINTZ Vd.4H,Vn.4H
float16x8_t vrndq_f16(float16x8_t a);                                // FRINTZ Vd.8H,Vn.8H
float16x4_t vrnda_f16(float16x4_t a);                                // FRINTA Vd.4H,Vn.4H
float16x8_t vrndaq_f16(float16x8_t a);                               // FRINTA Vd.8H,Vn.8H
float16x4_t vrndi_f16(float16x4_t a);                                // FRINTI Vd.4H,Vn.4H
float16x8_t vrndiq_f16(float16x8_t a);                               // FRINTI Vd.8H,Vn.8H
float16x4_t vrndm_f16(float16x4_t a);                                // FRINTM Vd.4H,Vn.4H
float16x8_t vrndmq_f16(float16x8_t a);                               // FRINTM Vd.8H,Vn.8H
float16x4_t vrndn_f16(float16x4_t a);                                // FRINTN Vd.4H,Vn.4H
float16x8_t vrndnq_f16(float16x8_t a);                               // FRINTN Vd.8H,Vn.8H
float16x4_t vrndp_f16(float16x4_t a);                                // FRINTP Vd.4H,Vn.4H
float16x8_t vrndpq_f16(float16x8_t a);                               // FRINTP Vd.8H,Vn.8H
float16x4_t vrndx_f16(float16x4_t a);                                // FRINTX Vd.4H,Vn.4H
float16x8_t vrndxq_f16(float16x8_t a);                               // FRINTX Vd.8H,Vn.8H
float16x4_t vrsqrte_f16(float16x4_t a);                              // FRSQRTE Vd.4H,Vn.4H
float16x8_t vrsqrteq_f16(float16x8_t a);                             // FRSQRTE Vd.8H,Vn.8H
float16x4_t vsqrt_f16(float16x4_t a);                                // FSQRT Vd.4H,Vn.4H
float16x8_t vsqrtq_f16(float16x8_t a);                               // FSQRT Vd.8H,Vn.8H
float16x4_t vadd_f16(float16x4_t a, float16x4_t b);                  // FADD Vd.4H,Vn.4H,Vm.4H
float16x8_t vaddq_f16(float16x8_t a, float16x8_t b);                 // FADD Vd.8H,Vn.8H,Vm.8H
float16x4_t vabd_f16(float16x4_t a, float16x4_t b);                  // FABD Vd.4H,Vn.4H,Vm.4H
float16x8_t vabdq_f16(float16x8_t a, float16x8_t b);                 // FABD Vd.8H,Vn.8H,Vm.8H
uint16x4_t vcage_f16(float16x4_t a, float16x4_t b);                  // FACGE Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcageq_f16(float16x8_t a, float16x8_t b);                 // FACGE Vd.8H,Vn.8H,Vm.8H
uint16x4_t vcagt_f16(float16x4_t a, float16x4_t b);                  // FACGT Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcagtq_f16(float16x8_t a, float16x8_t b);                 // FACGT Vd.8H,Vn.8H,Vm.8H
uint16x4_t vcale_f16(float16x4_t a, float16x4_t b);                  // FACGE Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcaleq_f16(float16x8_t a, float16x8_t b);                 // FACGE Vd.8H,Vn.8H,Vm.8H
uint16x4_t vcalt_f16(float16x4_t a, float16x4_t b);                  // FACGT Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcaltq_f16(float16x8_t a, float16x8_t b);                 // FACGT Vd.8H,Vn.8H,Vm.8H
uint16x4_t vceq_f16(float16x4_t a, float16x4_t b);                   // FCMEQ Vd.4H,Vn.4H,Vm.4H
uint16x8_t vceqq_f16(float16x8_t a, float16x8_t b);                  // FCMEQ Vd.8H,Vn.8H,Vm.8H
uint16x4_t vcge_f16(float16x4_t a, float16x4_t b);                   // FCMGE Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcgeq_f16(float16x8_t a, float16x8_t b);                  // FCMGE Vd.8H,Vn.8H,Vm.8H
uint16x4_t vcgt_f16(float16x4_t a, float16x4_t b);                   // FCMGT Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcgtq_f16(float16x8_t a, float16x8_t b);                  // FCMGT Vd.8H,Vn.8H,Vm.8H
uint16x4_t vcle_f16(float16x4_t a, float16x4_t b);                   // FCMGE Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcleq_f16(float16x8_t a, float16x8_t b);                  // FCMGE Vd.8H,Vn.8H,Vm.8H
uint16x4_t vclt_f16(float16x4_t a, float16x4_t b);                   // FCMGT Vd.4H,Vn.4H,Vm.4H
uint16x8_t vcltq_f16(float16x8_t a, float16x8_t b);                  // FCMGT Vd.8H,Vn.8H,Vm.8H
float16x4_t vcvt_n_f16_s16(int16x4_t a, const int n);                // SCVTF Vd.4H,Vn.4H,#n
float16x8_t vcvtq_n_f16_s16(int16x8_t a, const int n);               // SCVTF Vd.8H,Vn.8H,#n
float16x4_t vcvt_n_f16_u16(uint16x4_t a, const int n);               // UCVTF Vd.4H,Vn.4H,#n
float16x8_t vcvtq_n_f16_u16(uint16x8_t a, const int n);              // UCVTF Vd.8H,Vn.8H,#n
int16x4_t vcvt_n_s16_f16(float16x4_t a, const int n);                // FCVTZS Vd.4H,Vn.4H,#n
int16x8_t vcvtq_n_s16_f16(float16x8_t a, const int n);               // FCVTZS Vd.8H,Vn.8H,#n
uint16x4_t vcvt_n_u16_f16(float16x4_t a, const int n);               // FCVTZU Vd.4H,Vn.4H,#n
uint16x8_t vcvtq_n_u16_f16(float16x8_t a, const int n);              // FCVTZU Vd.8H,Vn.8H,#n
float16x4_t vdiv_f16(float16x4_t a, float16x4_t b);                  // FDIV Vd.4H,Vn.4H,Vm.4H
float16x8_t vdivq_f16(float16x8_t a, float16x8_t b);                 // FDIV Vd.8H,Vn.8H,Vm.8H
float16x4_t vmax_f16(float16x4_t a, float16x4_t b);                  // FMAX Vd.4H,Vn.4H,Vm.4H
float16x8_t vmaxq_f16(float16x8_t a, float16x8_t b);                 // FMAX Vd.8H,Vn.8H,Vm.8H
float16x4_t vmaxnm_f16(float16x4_t a, float16x4_t b);                // FMAXNM Vd.4H,Vn.4H,Vm.4H
float16x8_t vmaxnmq_f16(float16x8_t a, float16x8_t b);               // FMAXNM Vd.8H,Vn.8H,Vm.8H
float16x4_t vmin_f16(float16x4_t a, float16x4_t b);                  // FMIN Vd.4H,Vn.4H,Vm.4H
float16x8_t vminq_f16(float16x8_t a, float16x8_t b);                 // FMIN Vd.8H,Vn.8H,Vm.8H
float16x4_t vminnm_f16(float16x4_t a, float16x4_t b);                // FMINNM Vd.4H,Vn.4H,Vm.4H
float16x8_t vminnmq_f16(float16x8_t a, float16x8_t b);               // FMINNM Vd.8H,Vn.8H,Vm.8H
float16x4_t vmul_f16(float16x4_t a, float16x4_t b);                  // FMUL Vd.4H,Vn.4H,Vm.4H
float16x8_t vmulq_f16(float16x8_t a, float16x8_t b);                 // FMUL Vd.8H,Vn.8H,Vm.8H
float16x4_t vmulx_f16(float16x4_t a, float16x4_t b);                 // FMULX Vd.4H,Vn.4H,Vm.4H
float16x8_t vmulxq_f16(float16x8_t a, float16x8_t b);                // FMULX Vd.8H,Vn.8H,Vm.8H
float16x4_t vpadd_f16(float16x4_t a, float16x4_t b);                 // FADDP Vd.4H,Vn.4H,Vm.4H
float16x8_t vpaddq_f16(float16x8_t a, float16x8_t b);                // FADDP Vd.8H,Vn.8H,Vm.8H
float16x4_t vpmax_f16(float16x4_t a, float16x4_t b);                 // FMAXP Vd.4H,Vn.4H,Vm.4H
float16x8_t vpmaxq_f16(float16x8_t a, float16x8_t b);                // FMAXP Vd.8H,Vn.8H,Vm.8H
float16x4_t vpmaxnm_f16(float16x4_t a, float16x4_t b);               // FMAXNMP Vd.4H,Vn.4H,Vm.4H
float16x8_t vpmaxnmq_f16(float16x8_t a, float16x8_t b);              // FMAXNMP Vd.8H,Vn.8H,Vm.8H
float16x4_t vpmin_f16(float16x4_t a, float16x4_t b);                 // FMINP Vd.4H,Vn.4H,Vm.4H
float16x8_t vpminq_f16(float16x8_t a, float16x8_t b);                // FMINP Vd.8H,Vn.8H,Vm.8H
float16x4_t vpminnm_f16(float16x4_t a, float16x4_t b);               // FMINNMP Vd.4H,Vn.4H,Vm.4H
float16x8_t vpminnmq_f16(float16x8_t a, float16x8_t b);              // FMINNMP Vd.8H,Vn.8H,Vm.8H
float16x4_t vrecps_f16(float16x4_t a, float16x4_t b);                // FRECPS Vd.4H,Vn.4H,Vm.4H
float16x8_t vrecpsq_f16(float16x8_t a, float16x8_t b);               // FRECPS Vd.8H,Vn.8H,Vm.8H
float16x4_t vrsqrts_f16(float16x4_t a, float16x4_t b);               // FRSQRTS Vd.4H,Vn.4H,Vm.4H
float16x8_t vrsqrtsq_f16(float16x8_t a, float16x8_t b);              // FRSQRTS Vd.8H,Vn.8H,Vm.8H
float16x4_t vsub_f16(float16x4_t a, float16x4_t b);                  // FSUB Vd.4H,Vn.4H,Vm.4H
float16x8_t vsubq_f16(float16x8_t a, float16x8_t b);                 // FSUB Vd.8H,Vn.8H,Vm.8H
float16x4_t vfma_f16(float16x4_t a, float16x4_t b, float16x4_t c);   // FMLA Vd.4H,Vn.4H,Vm.4H
float16x8_t vfmaq_f16(float16x8_t a, float16x8_t b, float16x8_t c);  // FMLA Vd.8H,Vn.8H,Vm.8H
float16x4_t vfms_f16(float16x4_t a, float16x4_t b, float16x4_t c);   // FMLS Vd.4H,Vn.4H,Vm.4H
float16x8_t vfmsq_f16(float16x8_t a, float16x8_t b, float16x8_t c);  // FMLS Vd.8H,Vn.8H,Vm.8H
float16x4_t vfma_lane_f16(
    float16x4_t a, float16x4_t b, float16x4_t v, const int lane);  // FMLA Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vfmaq_lane_f16(
    float16x8_t a, float16x8_t b, float16x4_t v, const int lane);  // FMLA Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vfma_laneq_f16(
    float16x4_t a, float16x4_t b, float16x8_t v, const int lane);  // FMLA Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vfmaq_laneq_f16(
    float16x8_t a, float16x8_t b, float16x8_t v, const int lane);    // FMLA Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vfma_n_f16(float16x4_t a, float16x4_t b, float16_t n);   // FMLA Vd.4H,Vn.4H,Vm.H[0]
float16x8_t vfmaq_n_f16(float16x8_t a, float16x8_t b, float16_t n);  // FMLA Vd.8H,Vn.8H,Vm.H[0]
float16_t vfmah_lane_f16(
    float16_t a, float16_t b, float16x4_t v, const int lane);  // FMLA Hd,Hn,Vm.H[lane]
float16_t vfmah_laneq_f16(
    float16_t a, float16_t b, float16x8_t v, const int lane);  // FMLA Hd,Hn,Vm.H[lane]
float16x4_t vfms_lane_f16(
    float16x4_t a, float16x4_t b, float16x4_t v, const int lane);  // FMLS Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vfmsq_lane_f16(
    float16x8_t a, float16x8_t b, float16x4_t v, const int lane);  // FMLS Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vfms_laneq_f16(
    float16x4_t a, float16x4_t b, float16x8_t v, const int lane);  // FMLS Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vfmsq_laneq_f16(
    float16x8_t a, float16x8_t b, float16x8_t v, const int lane);    // FMLS Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vfms_n_f16(float16x4_t a, float16x4_t b, float16_t n);   // FMLS Vd.4H,Vn.4H,Vm.H[0]
float16x8_t vfmsq_n_f16(float16x8_t a, float16x8_t b, float16_t n);  // FMLS Vd.8H,Vn.8H,Vm.H[0]
float16_t vfmsh_lane_f16(
    float16_t a, float16_t b, float16x4_t v, const int lane);  // FMLS Hd,Hn,Vm.H[lane]
float16_t vfmsh_laneq_f16(
    float16_t a, float16_t b, float16x8_t v, const int lane);  // FMLS Hd,Hn,Vm.H[lane]
float16x4_t vmul_lane_f16(
    float16x4_t a, float16x4_t v, const int lane);  // FMUL Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vmulq_lane_f16(
    float16x8_t a, float16x4_t v, const int lane);  // FMUL Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vmul_laneq_f16(
    float16x4_t a, float16x8_t v, const int lane);  // FMUL Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vmulq_laneq_f16(
    float16x8_t a, float16x8_t v, const int lane);    // FMUL Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vmul_n_f16(float16x4_t a, float16_t n);   // FMUL Vd.4H,Vn.4H,Vm.H[0]
float16x8_t vmulq_n_f16(float16x8_t a, float16_t n);  // FMUL Vd.8H,Vn.8H,Vm.H[0]
float16_t vmulh_lane_f16(float16_t a, float16x4_t v, const int lane);   // FMUL Hd,Hn,Vm.H[lane]
float16_t vmulh_laneq_f16(float16_t a, float16x8_t v, const int lane);  // FMUL Hd,Hn,Vm.H[lane]
float16x4_t vmulx_lane_f16(
    float16x4_t a, float16x4_t v, const int lane);  // FMULX Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vmulxq_lane_f16(
    float16x8_t a, float16x4_t v, const int lane);  // FMULX Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vmulx_laneq_f16(
    float16x4_t a, float16x8_t v, const int lane);  // FMULX Vd.4H,Vn.4H,Vm.H[lane]
float16x8_t vmulxq_laneq_f16(
    float16x8_t a, float16x8_t v, const int lane);     // FMULX Vd.8H,Vn.8H,Vm.H[lane]
float16x4_t vmulx_n_f16(float16x4_t a, float16_t n);   // FMULX Vd.4H,Vn.4H,Vm.H[0]
float16x8_t vmulxq_n_f16(float16x8_t a, float16_t n);  // FMULX Vd.8H,Vn.8H,Vm.H[0]
float16_t vmulxh_lane_f16(float16_t a, float16x4_t v, const int lane);   // FMULX Hd,Hn,Vm.H[lane]
float16_t vmulxh_laneq_f16(float16_t a, float16x8_t v, const int lane);  // FMULX Hd,Hn,Vm.H[lane]
float16_t vmaxv_f16(float16x4_t a);                                      // FMAXP Hd,Vn.4H
float16_t vmaxvq_f16(float16x8_t a);                                     // FMAXP Hd,Vn.8H
float16_t vminv_f16(float16x4_t a);                                      // FMINP Hd,Vn.4H
float16_t vminvq_f16(float16x8_t a);                                     // FMINP Hd,Vn.8H
float16_t vmaxnmv_f16(float16x4_t a);                                    // FMAXNMP Hd,Vn.4H
float16_t vmaxnmvq_f16(float16x8_t a);                                   // FMAXNMP Hd,Vn.8H
float16_t vminnmv_f16(float16x4_t a);                                    // FMINNMP Hd,Vn.4H
float16_t vminnmvq_f16(float16x8_t a);                                   // FMINNMP Hd,Vn.8H
float16x4_t vbsl_f16(uint16x4_t a, float16x4_t b, float16x4_t c);        // BSL Vd.8B,Vn.8B,Vm.8B
float16x8_t vbslq_f16(uint16x8_t a, float16x8_t b, float16x8_t c);       // BSL Vd.16B,Vn.16B,Vm.16B
float16x4x2_t vzip_f16(
    float16x4_t a, float16x4_t b);  // ZIP1 Vd1.4H,Vn.4H,Vm.4H; ZIP2 Vd2.4H,Vn.4H,Vm.4H
float16x8x2_t vzipq_f16(
    float16x8_t a, float16x8_t b);  // ZIP1 Vd1.8H,Vn.8H,Vm.8H; ZIP2 Vd2.8H,Vn.8H,Vm.8H
float16x4x2_t vuzp_f16(
    float16x4_t a, float16x4_t b);  // UZP1 Vd1.4H,Vn.4H,Vm.4H; UZP2 Vd2.4H,Vn.4H,Vm.4H
float16x8x2_t vuzpq_f16(
    float16x8_t a, float16x8_t b);  // UZP1 Vd1.8H,Vn.8H,Vm.8H; UZP2 Vd2.8H,Vn.8H,Vm.8H
float16x4x2_t vtrn_f16(
    float16x4_t a, float16x4_t b);  // TRN1 Vd1.4H,Vn.4H,Vm.4H; TRN2 Vd2.4H,Vn.4H,Vm.4H
float16x8x2_t vtrnq_f16(
    float16x8_t a, float16x8_t b);         // TRN1 Vd1.8H,Vn.8H,Vm.8H; TRN2 Vd2.8H,Vn.8H,Vm.8H
float16x4_t vmov_n_f16(float16_t value);   // DUP Vd.4H,rn
float16x8_t vmovq_n_f16(float16_t value);  // DUP Vd.8H,rn
float16x4_t vdup_n_f16(float16_t value);   // DUP Vd.4H,rn
float16x8_t vdupq_n_f16(float16_t value);  // DUP Vd.8H,rn
float16x4_t vdup_lane_f16(float16x4_t vec, const int lane);       // DUP Vd.4H,Vn.H[lane]
float16x8_t vdupq_lane_f16(float16x4_t vec, const int lane);      // DUP Vd.8H,Vn.H[lane]
float16x4_t vext_f16(float16x4_t a, float16x4_t b, const int n);  // EXT Vd.8B,Vn.8B,Vm.8B,#(n<<1)
float16x8_t vextq_f16(
    float16x8_t a, float16x8_t b, const int n);                  // EXT Vd.16B,Vn.16B,Vm.16B,#(n<<1)
float16x4_t vrev64_f16(float16x4_t vec);                         // REV64 Vd.4H,Vn.4H
float16x8_t vrev64q_f16(float16x8_t vec);                        // REV64 Vd.8H,Vn.8H
float16x4_t vzip1_f16(float16x4_t a, float16x4_t b);             // ZIP1 Vd.4H,Vn.4H,Vm.4H
float16x8_t vzip1q_f16(float16x8_t a, float16x8_t b);            // ZIP1 Vd.8H,Vn.8H,Vm.8H
float16x4_t vzip2_f16(float16x4_t a, float16x4_t b);             // ZIP2 Vd.4H,Vn.4H,Vm.4H
float16x8_t vzip2q_f16(float16x8_t a, float16x8_t b);            // ZIP2 Vd.8H,Vn.8H,Vm.8H
float16x4_t vuzp1_f16(float16x4_t a, float16x4_t b);             // UZP1 Vd.4H,Vn.4H,Vm.4H
float16x8_t vuzp1q_f16(float16x8_t a, float16x8_t b);            // UZP1 Vd.8H,Vn.8H,Vm.8H
float16x4_t vuzp2_f16(float16x4_t a, float16x4_t b);             // UZP2 Vd.4H,Vn.4H,Vm.4H
float16x8_t vuzp2q_f16(float16x8_t a, float16x8_t b);            // UZP2 Vd.8H,Vn.8H,Vm.8H
float16x4_t vtrn1_f16(float16x4_t a, float16x4_t b);             // TRN1 Vd.4H,Vn.4H,Vm.4H
float16x8_t vtrn1q_f16(float16x8_t a, float16x8_t b);            // TRN1 Vd.8H,Vn.8H,Vm.8H
float16x4_t vtrn2_f16(float16x4_t a, float16x4_t b);             // TRN2 Vd.4H,Vn.4H,Vm.4H
float16x8_t vtrn2q_f16(float16x8_t a, float16x8_t b);            // TRN2 Vd.8H,Vn.8H,Vm.8H
float16x4_t vdup_laneq_f16(float16x8_t vec, const int lane);     // DUP Vd.4H,Vn.H[lane]
float16x8_t vdupq_laneq_f16(float16x8_t vec, const int lane);    // DUP Vd.8H,Vn.H[lane]
float16_t vduph_lane_f16(float16x4_t vec, const int lane);       // DUP Hd,Vn.H[lane]
float16_t vduph_laneq_f16(float16x8_t vec, const int lane);      // DUP Hd,Vn.H[lane]
uint32x2_t vdot_u32(uint32x2_t r, uint8x8_t a, uint8x8_t b);     // UDOT Vd.2S,Vn.8B,Vm.8B
int32x2_t vdot_s32(int32x2_t r, int8x8_t a, int8x8_t b);         // SDOT Vd.2S,Vn.8B,Vm.8B
uint32x4_t vdotq_u32(uint32x4_t r, uint8x16_t a, uint8x16_t b);  // UDOT Vd.4S,Vn.16B,Vm.16B
int32x4_t vdotq_s32(int32x4_t r, int8x16_t a, int8x16_t b);      // SDOT Vd.4S,Vn.16B,Vm.16B
uint32x2_t vdot_lane_u32(
    uint32x2_t r, uint8x8_t a, uint8x8_t b, const int lane);  // UDOT Vd.2S,Vn.8B,Vm.4B[lane]
int32x2_t vdot_lane_s32(
    int32x2_t r, int8x8_t a, int8x8_t b, const int lane);  // SDOT Vd.2S,Vn.8B,Vm.4B[lane]
uint32x4_t vdotq_laneq_u32(
    uint32x4_t r, uint8x16_t a, uint8x16_t b, const int lane);  // UDOT Vd.4S,Vn.16B,Vm.4B[lane]
int32x4_t vdotq_laneq_s32(
    int32x4_t r, int8x16_t a, int8x16_t b, const int lane);  // SDOT Vd.4S,Vn.16B,Vm.4B[lane]
uint32x2_t vdot_laneq_u32(
    uint32x2_t r, uint8x8_t a, uint8x16_t b, const int lane);  // UDOT Vd.2S,Vn.8B,Vm.4B[lane]
int32x2_t vdot_laneq_s32(
    int32x2_t r, int8x8_t a, int8x16_t b, const int lane);  // SDOT Vd.2S,Vn.8B,Vm.4B[lane]
uint32x4_t vdotq_lane_u32(
    uint32x4_t r, uint8x16_t a, uint8x8_t b, const int lane);  // UDOT Vd.4S,Vn.16B,Vm.4B[lane]
int32x4_t vdotq_lane_s32(
    int32x4_t r, int8x16_t a, int8x8_t b, const int lane);  // SDOT Vd.4S,Vn.16B,Vm.4B[lane]
uint64x2_t vsha512hq_u64(
    uint64x2_t hash_ed, uint64x2_t hash_gf, uint64x2_t kwh_kwh2);  // SHA512H Qd,Qn,Vm.2D
uint64x2_t vsha512h2q_u64(
    uint64x2_t sum_ab, uint64x2_t hash_c_, uint64x2_t hash_ab);  // SHA512H2 Qd,Qn,Vm.2D
uint64x2_t vsha512su0q_u64(uint64x2_t w0_1, uint64x2_t w2_);     // SHA512SU0 Vd.2D,Vn.2D
uint64x2_t vsha512su1q_u64(
    uint64x2_t s01_s02, uint64x2_t w14_15, uint64x2_t w9_10);    // SHA512SU1 Vd.2D,Vn.2D,Vm.2D
uint8x16_t veor3q_u8(uint8x16_t a, uint8x16_t b, uint8x16_t c);  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
uint16x8_t veor3q_u16(
    uint16x8_t a, uint16x8_t b, uint16x8_t c);  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
uint32x4_t veor3q_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c);  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
uint64x2_t veor3q_u64(
    uint64x2_t a, uint64x2_t b, uint64x2_t c);                // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
int8x16_t veor3q_s8(int8x16_t a, int8x16_t b, int8x16_t c);   // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
int16x8_t veor3q_s16(int16x8_t a, int16x8_t b, int16x8_t c);  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
int32x4_t veor3q_s32(int32x4_t a, int32x4_t b, int32x4_t c);  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
int64x2_t veor3q_s64(int64x2_t a, int64x2_t b, int64x2_t c);  // EOR3 Vd.16B,Vn.16B,Vm.16B,Va.16B
uint64x2_t vrax1q_u64(uint64x2_t a, uint64x2_t b);            // RAX1 Vd.2D,Vn.2D,Vm.2D
uint64x2_t vxarq_u64(uint64x2_t a, uint64x2_t b, const int imm6);  // XAR Vd.2D,Vn.2D,Vm.2D,imm6
uint8x16_t vbcaxq_u8(uint8x16_t a, uint8x16_t b, uint8x16_t c);  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
uint16x8_t vbcaxq_u16(
    uint16x8_t a, uint16x8_t b, uint16x8_t c);  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
uint32x4_t vbcaxq_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c);  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
uint64x2_t vbcaxq_u64(
    uint64x2_t a, uint64x2_t b, uint64x2_t c);                // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
int8x16_t vbcaxq_s8(int8x16_t a, int8x16_t b, int8x16_t c);   // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
int16x8_t vbcaxq_s16(int16x8_t a, int16x8_t b, int16x8_t c);  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
int32x4_t vbcaxq_s32(int32x4_t a, int32x4_t b, int32x4_t c);  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
int64x2_t vbcaxq_s64(int64x2_t a, int64x2_t b, int64x2_t c);  // BCAX Vd.16B,Vn.16B,Vm.16B,Va.16B
uint32x4_t vsm3ss1q_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c);  // SM3SS1 Vd.4S,Vn.4S,Vm.4S,Va.4S
uint32x4_t vsm3tt1aq_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c, const int imm2);  // SM3TT1A Vd.4S,Vn.4S,Vm.4S[imm2]
uint32x4_t vsm3tt1bq_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c, const int imm2);  // SM3TT1B Vd.4S,Vn.4S,Vm.4S[imm2]
uint32x4_t vsm3tt2aq_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c, const int imm2);  // SM3TT2A Vd.4S,Vn.4S,Vm.4S[imm2]
uint32x4_t vsm3tt2bq_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c, const int imm2);  // SM3TT2B Vd.4S,Vn.4S,Vm.4S[imm2]
uint32x4_t vsm3partw1q_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c);  // SM3PARTW1 Vd.4S,Vn.4S,Vm.4S
uint32x4_t vsm3partw2q_u32(
    uint32x4_t a, uint32x4_t b, uint32x4_t c);         // SM3PARTW2 Vd.4S,Vn.4S,Vm.4S
uint32x4_t vsm4eq_u32(uint32x4_t a, uint32x4_t b);     // SM4E Vd.4S,Vn.4S
uint32x4_t vsm4ekeyq_u32(uint32x4_t a, uint32x4_t b);  // SM4EKEY Vd.4S,Vn.4S,Vm.4S
float32x2_t vfmlal_low_f16(float32x2_t r, float16x4_t a, float16x4_t b);  // FMLAL Vd.2S,Vn.2H,Vm.2H
float32x2_t vfmlsl_low_f16(float32x2_t r, float16x4_t a, float16x4_t b);  // FMLSL Vd.2S,Vn.2H,Vm.2H
float32x4_t vfmlalq_low_f16(
    float32x4_t r, float16x8_t a, float16x8_t b);  // FMLAL Vd.4S,Vn.4H,Vm.4H
float32x4_t vfmlslq_low_f16(
    float32x4_t r, float16x8_t a, float16x8_t b);  // FMLSL Vd.4S,Vn.4H,Vm.4H
float32x2_t vfmlal_high_f16(
    float32x2_t r, float16x4_t a, float16x4_t b);  // FMLAL2 Vd.2S,Vn.2H,Vm.2H
float32x2_t vfmlsl_high_f16(
    float32x2_t r, float16x4_t a, float16x4_t b);  // FMLSL2 Vd.2S,Vn.2H,Vm.2H
float32x4_t vfmlalq_high_f16(
    float32x4_t r, float16x8_t a, float16x8_t b);  // FMLAL2 Vd.4S,Vn.4H,Vm.4H
float32x4_t vfmlslq_high_f16(
    float32x4_t r, float16x8_t a, float16x8_t b);  // FMLSL2 Vd.4S,Vn.4H,Vm.4H
float32x2_t vfmlal_lane_low_f16(
    float32x2_t r, float16x4_t a, float16x4_t b, const int lane);  // FMLAL Vd.2S,Vn.2H,Vm.H[lane]
float32x2_t vfmlal_laneq_low_f16(
    float32x2_t r, float16x4_t a, float16x8_t b, const int lane);  // FMLAL Vd.2S,Vn.2H,Vm.H[lane]
float32x4_t vfmlalq_lane_low_f16(
    float32x4_t r, float16x8_t a, float16x4_t b, const int lane);  // FMLAL Vd.4S,Vn.4H,Vm.H[lane]
float32x4_t vfmlalq_laneq_low_f16(
    float32x4_t r, float16x8_t a, float16x8_t b, const int lane);  // FMLAL Vd.4S,Vn.4H,Vm.H[lane]
float32x2_t vfmlsl_lane_low_f16(
    float32x2_t r, float16x4_t a, float16x4_t b, const int lane);  // FMLSL Vd.2S,Vn.2H,Vm.H[lane]
float32x2_t vfmlsl_laneq_low_f16(
    float32x2_t r, float16x4_t a, float16x8_t b, const int lane);  // FMLSL Vd.2S,Vn.2H,Vm.H[lane]
float32x4_t vfmlslq_lane_low_f16(
    float32x4_t r, float16x8_t a, float16x4_t b, const int lane);  // FMLSL Vd.4S,Vn.4H,Vm.H[lane]
float32x4_t vfmlslq_laneq_low_f16(
    float32x4_t r, float16x8_t a, float16x8_t b, const int lane);  // FMLSL Vd.4S,Vn.4H,Vm.H[lane]
float32x2_t vfmlal_lane_high_f16(
    float32x2_t r, float16x4_t a, float16x4_t b, const int lane);  // FMLAL2 Vd.2S,Vn.2H,Vm.H[lane]
float32x2_t vfmlsl_lane_high_f16(
    float32x2_t r, float16x4_t a, float16x4_t b, const int lane);  // FMLSL2 Vd.2S,Vn.2H,Vm.H[lane]
float32x4_t vfmlalq_lane_high_f16(
    float32x4_t r, float16x8_t a, float16x4_t b, const int lane);  // FMLAL2 Vd.4S,Vn.4H,Vm.H[lane]
float32x4_t vfmlslq_lane_high_f16(
    float32x4_t r, float16x8_t a, float16x4_t b, const int lane);  // FMLSL2 Vd.4S,Vn.4H,Vm.H[lane]
float32x2_t vfmlal_laneq_high_f16(
    float32x2_t r, float16x4_t a, float16x8_t b, const int lane);  // FMLAL2 Vd.2S,Vn.2H,Vm.H[lane]
float32x2_t vfmlsl_laneq_high_f16(
    float32x2_t r, float16x4_t a, float16x8_t b, const int lane);  // FMLSL2 Vd.2S,Vn.2H,Vm.H[lane]
float32x4_t vfmlalq_laneq_high_f16(
    float32x4_t r, float16x8_t a, float16x8_t b, const int lane);  // FMLAL2 Vd.4S,Vn.4H,Vm.H[lane]
float32x4_t vfmlslq_laneq_high_f16(
    float32x4_t r, float16x8_t a, float16x8_t b, const int lane);  // FMLSL2 Vd.4S,Vn.4H,Vm.H[lane]
float16x4_t vcadd_rot90_f16(float16x4_t a, float16x4_t b);         // FCADD Vd.4H,Vn.4H,Vm.4H,#90
float32x2_t vcadd_rot90_f32(float32x2_t a, float32x2_t b);         // FCADD Vd.2S,Vn.2S,Vm.2S,#90
float16x8_t vcaddq_rot90_f16(float16x8_t a, float16x8_t b);        // FCADD Vd.8H,Vn.8H,Vm.8H,#90
float32x4_t vcaddq_rot90_f32(float32x4_t a, float32x4_t b);        // FCADD Vd.4S,Vn.4S,Vm.4S,#90
float64x2_t vcaddq_rot90_f64(float64x2_t a, float64x2_t b);        // FCADD Vd.2D,Vn.2D,Vm.2D,#90
float16x4_t vcadd_rot270_f16(float16x4_t a, float16x4_t b);        // FCADD Vd.4H,Vn.4H,Vm.4H,#270
float32x2_t vcadd_rot270_f32(float32x2_t a, float32x2_t b);        // FCADD Vd.2S,Vn.2S,Vm.2S,#270
float16x8_t vcaddq_rot270_f16(float16x8_t a, float16x8_t b);       // FCADD Vd.8H,Vn.8H,Vm.8H,#270
float32x4_t vcaddq_rot270_f32(float32x4_t a, float32x4_t b);       // FCADD Vd.4S,Vn.4S,Vm.4S,#270
float64x2_t vcaddq_rot270_f64(float64x2_t a, float64x2_t b);       // FCADD Vd.2D,Vn.2D,Vm.2D,#270
float16x4_t vcmla_f16(float16x4_t r, float16x4_t a, float16x4_t b);  // FCMLA Vd.4H,Vn.4H,Vm.4H,#0
float32x2_t vcmla_f32(float32x2_t r, float32x2_t a, float32x2_t b);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#0
float16x4_t vcmla_lane_f16(float16x4_t r, float16x4_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#0
float32x2_t vcmla_lane_f32(
    float32x2_t r, float32x2_t a, float32x2_t b, const int lane);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#0
float16x4_t vcmla_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#0
float16x4_t vcmla_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.4H,Vn.4H,Vm.H[lane % 2],#0
float32x2_t vcmla_laneq_f32(float32x2_t r, float32x2_t a, float32x4_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.2S,Vn.2S,Vm.2S,#0
float16x8_t vcmlaq_f16(float16x8_t r, float16x8_t a, float16x8_t b);  // FCMLA Vd.8H,Vn.8H,Vm.8H,#0
float32x4_t vcmlaq_f32(float32x4_t r, float32x4_t a, float32x4_t b);  // FCMLA Vd.4S,Vn.4S,Vm.4S,#0
float64x2_t vcmlaq_f64(float64x2_t r, float64x2_t a, float64x2_t b);  // FCMLA Vd.2D,Vn.2D,Vm.2D,#0
float16x8_t vcmlaq_lane_f16(float16x8_t r, float16x8_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#0
float32x4_t vcmlaq_lane_f32(float32x4_t r, float32x4_t a, float32x2_t b,
    const int lane);  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#0
float16x8_t vcmlaq_laneq_f16(float16x8_t r, float16x8_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#0
float32x4_t vcmlaq_laneq_f32(float32x4_t r, float32x4_t a, float32x4_t b,
    const int lane);  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#0
float16x4_t vcmla_rot90_f16(
    float16x4_t r, float16x4_t a, float16x4_t b);  // FCMLA Vd.4H,Vn.4H,Vm.4H,#90
float32x2_t vcmla_rot90_f32(
    float32x2_t r, float32x2_t a, float32x2_t b);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#90
float16x4_t vcmla_rot90_lane_f16(float16x4_t r, float16x4_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#90
float32x2_t vcmla_rot90_lane_f32(
    float32x2_t r, float32x2_t a, float32x2_t b, const int lane);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#90
float16x4_t vcmla_rot90_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#90
float16x4_t vcmla_rot90_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.4H,Vn.4H,Vm.H[lane % 2],#90
float32x2_t vcmla_rot90_laneq_f32(float32x2_t r, float32x2_t a, float32x4_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.2S,Vn.2S,Vm.2S,#90
float16x8_t vcmlaq_rot90_f16(
    float16x8_t r, float16x8_t a, float16x8_t b);  // FCMLA Vd.8H,Vn.8H,Vm.8H,#90
float32x4_t vcmlaq_rot90_f32(
    float32x4_t r, float32x4_t a, float32x4_t b);  // FCMLA Vd.4S,Vn.4S,Vm.4S,#90
float64x2_t vcmlaq_rot90_f64(
    float64x2_t r, float64x2_t a, float64x2_t b);  // FCMLA Vd.2D,Vn.2D,Vm.2D,#90
float16x8_t vcmlaq_rot90_lane_f16(float16x8_t r, float16x8_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#90
float32x4_t vcmlaq_rot90_lane_f32(float32x4_t r, float32x4_t a, float32x2_t b,
    const int lane);  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#90
float16x8_t vcmlaq_rot90_laneq_f16(float16x8_t r, float16x8_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#90
float32x4_t vcmlaq_rot90_laneq_f32(float32x4_t r, float32x4_t a, float32x4_t b,
    const int lane);  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#90
float16x4_t vcmla_rot180_f16(
    float16x4_t r, float16x4_t a, float16x4_t b);  // FCMLA Vd.4H,Vn.4H,Vm.4H,#180
float32x2_t vcmla_rot180_f32(
    float32x2_t r, float32x2_t a, float32x2_t b);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#180
float16x4_t vcmla_rot180_lane_f16(float16x4_t r, float16x4_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#180
float32x2_t vcmla_rot180_lane_f32(
    float32x2_t r, float32x2_t a, float32x2_t b, const int lane);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#180
float16x4_t vcmla_rot180_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#180
float16x4_t vcmla_rot180_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.4H,Vn.4H,Vm.H[lane % 2],#180
float32x2_t vcmla_rot180_laneq_f32(float32x2_t r, float32x2_t a, float32x4_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.2S,Vn.2S,Vm.2S,#180
float16x8_t vcmlaq_rot180_f16(
    float16x8_t r, float16x8_t a, float16x8_t b);  // FCMLA Vd.8H,Vn.8H,Vm.8H,#180
float32x4_t vcmlaq_rot180_f32(
    float32x4_t r, float32x4_t a, float32x4_t b);  // FCMLA Vd.4S,Vn.4S,Vm.4S,#180
float64x2_t vcmlaq_rot180_f64(
    float64x2_t r, float64x2_t a, float64x2_t b);  // FCMLA Vd.2D,Vn.2D,Vm.2D,#180
float16x8_t vcmlaq_rot180_lane_f16(float16x8_t r, float16x8_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#180
float32x4_t vcmlaq_rot180_lane_f32(float32x4_t r, float32x4_t a, float32x2_t b,
    const int lane);  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#180
float16x8_t vcmlaq_rot180_laneq_f16(float16x8_t r, float16x8_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#180
float32x4_t vcmlaq_rot180_laneq_f32(float32x4_t r, float32x4_t a, float32x4_t b,
    const int lane);  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#180
float16x4_t vcmla_rot270_f16(
    float16x4_t r, float16x4_t a, float16x4_t b);  // FCMLA Vd.4H,Vn.4H,Vm.4H,#270
float32x2_t vcmla_rot270_f32(
    float32x2_t r, float32x2_t a, float32x2_t b);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#270
float16x4_t vcmla_rot270_lane_f16(float16x4_t r, float16x4_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#270
float32x2_t vcmla_rot270_lane_f32(
    float32x2_t r, float32x2_t a, float32x2_t b, const int lane);  // FCMLA Vd.2S,Vn.2S,Vm.2S,#270
float16x4_t vcmla_rot270_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.4H,Vn.4H,Vm.H[lane],#270
float16x4_t vcmla_rot270_laneq_f16(float16x4_t r, float16x4_t a, float16x8_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.4H,Vn.4H,Vm.H[lane % 2],#270
float32x2_t vcmla_rot270_laneq_f32(float32x2_t r, float32x2_t a, float32x4_t b,
    const int lane);  // DUP Dm,Vm.D[1]; FCMLA Vd.2S,Vn.2S,Vm.2S,#270
float16x8_t vcmlaq_rot270_f16(
    float16x8_t r, float16x8_t a, float16x8_t b);  // FCMLA Vd.8H,Vn.8H,Vm.8H,#270
float32x4_t vcmlaq_rot270_f32(
    float32x4_t r, float32x4_t a, float32x4_t b);  // FCMLA Vd.4S,Vn.4S,Vm.4S,#270
float64x2_t vcmlaq_rot270_f64(
    float64x2_t r, float64x2_t a, float64x2_t b);  // FCMLA Vd.2D,Vn.2D,Vm.2D,#270
float16x8_t vcmlaq_rot270_lane_f16(float16x8_t r, float16x8_t a, float16x4_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#270
float32x4_t vcmlaq_rot270_lane_f32(float32x4_t r, float32x4_t a, float32x2_t b,
    const int lane);  // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#270
float16x8_t vcmlaq_rot270_laneq_f16(float16x8_t r, float16x8_t a, float16x8_t b,
    const int lane);  // FCMLA Vd.8H,Vn.8H,Vm.H[lane],#270
float32x4_t vcmlaq_rot270_laneq_f32(float32x4_t r, float32x4_t a, float32x4_t b,
    const int lane);                                          // FCMLA Vd.4S,Vn.4S,Vm.S[lane],#270
float32x2_t vrnd32z_f32(float32x2_t a);                       // FRINT32Z Vd.2S,Vn.2S
float32x4_t vrnd32zq_f32(float32x4_t a);                      // FRINT32Z Vd.4S,Vn.4S
float64x1_t vrnd32z_f64(float64x1_t a);                       // FRINT32Z Dd,Dn
float64x2_t vrnd32zq_f64(float64x2_t a);                      // FRINT32Z Vd.2D,Vn.2D
float32x2_t vrnd64z_f32(float32x2_t a);                       // FRINT64Z Vd.2S,Vn.2S
float32x4_t vrnd64zq_f32(float32x4_t a);                      // FRINT64Z Vd.4S,Vn.4S
float64x1_t vrnd64z_f64(float64x1_t a);                       // FRINT64Z Dd,Dn
float64x2_t vrnd64zq_f64(float64x2_t a);                      // FRINT64Z Vd.2D,Vn.2D
float32x2_t vrnd32x_f32(float32x2_t a);                       // FRINT32X Vd.2S,Vn.2S
float32x4_t vrnd32xq_f32(float32x4_t a);                      // FRINT32X Vd.4S,Vn.4S
float64x1_t vrnd32x_f64(float64x1_t a);                       // FRINT32X Dd,Dn
float64x2_t vrnd32xq_f64(float64x2_t a);                      // FRINT32X Vd.2D,Vn.2D
float32x2_t vrnd64x_f32(float32x2_t a);                       // FRINT64X Vd.2S,Vn.2S
float32x4_t vrnd64xq_f32(float32x4_t a);                      // FRINT64X Vd.4S,Vn.4S
float64x1_t vrnd64x_f64(float64x1_t a);                       // FRINT64X Dd,Dn
float64x2_t vrnd64xq_f64(float64x2_t a);                      // FRINT64X Vd.2D,Vn.2D
int32x4_t vmmlaq_s32(int32x4_t r, int8x16_t a, int8x16_t b);  // SMMLA Vd.4S,Vn.16B,Vm.16B
uint32x4_t vmmlaq_u32(uint32x4_t r, uint8x16_t a, uint8x16_t b);  // UMMLA Vd.4S,Vn.16B,Vm.16B
int32x4_t vusmmlaq_s32(int32x4_t r, uint8x16_t a, int8x16_t b);   // USMMLA Vd.4S,Vn.16B,Vm.16B
int32x2_t vusdot_s32(int32x2_t r, uint8x8_t a, int8x8_t b);       // USDOT Vd.2S,Vn.8B,Vm.8B
int32x2_t vusdot_lane_s32(
    int32x2_t r, uint8x8_t a, int8x8_t b, const int lane);  // USDOT Vd.2S,Vn.8B,Vm.4B[lane]
int32x2_t vsudot_lane_s32(
    int32x2_t r, int8x8_t a, uint8x8_t b, const int lane);  // SUDOT Vd.2S,Vn.8B,Vm.4B[lane]
int32x2_t vusdot_laneq_s32(
    int32x2_t r, uint8x8_t a, int8x16_t b, const int lane);  // USDOT Vd.2S,Vn.8B,Vm.4B[lane]
int32x2_t vsudot_laneq_s32(
    int32x2_t r, int8x8_t a, uint8x16_t b, const int lane);     // SUDOT Vd.2S,Vn.8B,Vm.4B[lane]
int32x4_t vusdotq_s32(int32x4_t r, uint8x16_t a, int8x16_t b);  // USDOT Vd.4S,Vn.16B,Vm.16B
int32x4_t vusdotq_lane_s32(
    int32x4_t r, uint8x16_t a, int8x8_t b, const int lane);  // USDOT Vd.4S,Vn.16B,Vm.4B[lane]
int32x4_t vsudotq_lane_s32(
    int32x4_t r, int8x16_t a, uint8x8_t b, const int lane);  // SUDOT Vd.4S,Vn.16B,Vm.4B[lane]
int32x4_t vusdotq_laneq_s32(
    int32x4_t r, uint8x16_t a, int8x16_t b, const int lane);  // USDOT Vd.4S,Vn.16B,Vm.4B[lane]
int32x4_t vsudotq_laneq_s32(
    int32x4_t r, int8x16_t a, uint8x16_t b, const int lane);      // SUDOT Vd.4S,Vn.16B,Vm.4B[lane]
bfloat16x4_t vcreate_bf16(uint64_t a);                            // INS Vd.D[0],Xn
bfloat16x4_t vdup_n_bf16(bfloat16_t value);                       // DUP Vd.4H,rn
bfloat16x8_t vdupq_n_bf16(bfloat16_t value);                      // DUP Vd.8H,rn
bfloat16x4_t vdup_lane_bf16(bfloat16x4_t vec, const int lane);    // DUP Vd.4H,Vn.H[lane]
bfloat16x8_t vdupq_lane_bf16(bfloat16x4_t vec, const int lane);   // DUP Vd.8H,Vn.H[lane]
bfloat16x4_t vdup_laneq_bf16(bfloat16x8_t vec, const int lane);   // DUP Vd.4H,Vn.H[lane]
bfloat16x8_t vdupq_laneq_bf16(bfloat16x8_t vec, const int lane);  // DUP Vd.8H,Vn.H[lane]
bfloat16x8_t vcombine_bf16(
    bfloat16x4_t low, bfloat16x4_t high);     // DUP Vd.1D,Vn.D[0]; INS Vd.D[1],Vm.D[0]
bfloat16x4_t vget_high_bf16(bfloat16x8_t a);  // DUP Vd.1D,Vn.D[1]
bfloat16x4_t vget_low_bf16(bfloat16x8_t a);   // DUP Vd.1D,Vn.D[0]
bfloat16_t vget_lane_bf16(bfloat16x4_t v, const int lane);   // DUP Hd,Vn.H[lane]
bfloat16_t vgetq_lane_bf16(bfloat16x8_t v, const int lane);  // DUP Hd,Vn.H[lane]
bfloat16x4_t vset_lane_bf16(
    bfloat16_t a, bfloat16x4_t v, const int lane);  // INS Vd.H[lane],Vn.H[0]
bfloat16x8_t vsetq_lane_bf16(
    bfloat16_t a, bfloat16x8_t v, const int lane);              // INS Vd.H[lane],Vn.H[0]
bfloat16_t vduph_lane_bf16(bfloat16x4_t vec, const int lane);   // DUP Hd,Vn.H[lane]
bfloat16_t vduph_laneq_bf16(bfloat16x8_t vec, const int lane);  // DUP Hd,Vn.H[lane]
bfloat16x4_t vld1_bf16(bfloat16_t const* ptr);                  // LD1 {Vt.4H},[Xn]
bfloat16x8_t vld1q_bf16(bfloat16_t const* ptr);                 // LD1 {Vt.8H},[Xn]
bfloat16x4_t vld1_lane_bf16(
    bfloat16_t const* ptr, bfloat16x4_t src, const int lane);  // LD1 {Vt.H}[lane],[Xn]
bfloat16x8_t vld1q_lane_bf16(
    bfloat16_t const* ptr, bfloat16x8_t src, const int lane);             // LD1 {Vt.H}[lane],[Xn]
bfloat16x4_t vld1_dup_bf16(bfloat16_t const* ptr);                        // LD1R {Vt.4H},[Xn]
bfloat16x8_t vld1q_dup_bf16(bfloat16_t const* ptr);                       // LD1R {Vt.8H},[Xn]
void vst1_bf16(bfloat16_t* ptr, bfloat16x4_t val);                        // ST1 {Vt.4H},[Xn]
void vst1q_bf16(bfloat16_t* ptr, bfloat16x8_t val);                       // ST1 {Vt.8H},[Xn]
void vst1_lane_bf16(bfloat16_t* ptr, bfloat16x4_t val, const int lane);   // ST1 {Vt.h}[lane],[Xn]
void vst1q_lane_bf16(bfloat16_t* ptr, bfloat16x8_t val, const int lane);  // ST1 {Vt.h}[lane],[Xn]
bfloat16x4x2_t vld2_bf16(bfloat16_t const* ptr);       // LD2 {Vt.4H - Vt2.4H},[Xn]
bfloat16x8x2_t vld2q_bf16(bfloat16_t const* ptr);      // LD2 {Vt.8H - Vt2.8H},[Xn]
bfloat16x4x3_t vld3_bf16(bfloat16_t const* ptr);       // LD3 {Vt.4H - Vt3.4H},[Xn]
bfloat16x8x3_t vld3q_bf16(bfloat16_t const* ptr);      // LD3 {Vt.8H - Vt3.8H},[Xn]
bfloat16x4x4_t vld4_bf16(bfloat16_t const* ptr);       // LD4 {Vt.4H - Vt4.4H},[Xn]
bfloat16x8x4_t vld4q_bf16(bfloat16_t const* ptr);      // LD4 {Vt.8H - Vt4.8H},[Xn]
bfloat16x4x2_t vld2_dup_bf16(bfloat16_t const* ptr);   // LD2R {Vt.4H - Vt2.4H},[Xn]
bfloat16x8x2_t vld2q_dup_bf16(bfloat16_t const* ptr);  // LD2R {Vt.8H - Vt2.8H},[Xn]
bfloat16x4x3_t vld3_dup_bf16(bfloat16_t const* ptr);   // LD3R {Vt.4H - Vt3.4H},[Xn]
bfloat16x8x3_t vld3q_dup_bf16(bfloat16_t const* ptr);  // LD3R {Vt.8H - Vt3.8H},[Xn]
bfloat16x4x4_t vld4_dup_bf16(bfloat16_t const* ptr);   // LD4R {Vt.4H - Vt4.4H},[Xn]
bfloat16x8x4_t vld4q_dup_bf16(bfloat16_t const* ptr);  // LD4R {Vt.8H - Vt4.8H},[Xn]
void vst2_bf16(bfloat16_t* ptr, bfloat16x4x2_t val);   // ST2 {Vt.4H - Vt2.4H},[Xn]
void vst2q_bf16(bfloat16_t* ptr, bfloat16x8x2_t val);  // ST2 {Vt.8H - Vt2.8H},[Xn]
void vst3_bf16(bfloat16_t* ptr, bfloat16x4x3_t val);   // ST3 {Vt.4H - Vt3.4H},[Xn]
void vst3q_bf16(bfloat16_t* ptr, bfloat16x8x3_t val);  // ST3 {Vt.8H - Vt3.8H},[Xn]
void vst4_bf16(bfloat16_t* ptr, bfloat16x4x4_t val);   // ST4 {Vt.4H - Vt4.4H},[Xn]
void vst4q_bf16(bfloat16_t* ptr, bfloat16x8x4_t val);  // ST4 {Vt.8H - Vt4.8H},[Xn]
bfloat16x4x2_t vld2_lane_bf16(
    bfloat16_t const* ptr, bfloat16x4x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
bfloat16x8x2_t vld2q_lane_bf16(
    bfloat16_t const* ptr, bfloat16x8x2_t src, const int lane);  // LD2 {Vt.h - Vt2.h}[lane],[Xn]
bfloat16x4x3_t vld3_lane_bf16(
    bfloat16_t const* ptr, bfloat16x4x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
bfloat16x8x3_t vld3q_lane_bf16(
    bfloat16_t const* ptr, bfloat16x8x3_t src, const int lane);  // LD3 {Vt.h - Vt3.h}[lane],[Xn]
bfloat16x4x4_t vld4_lane_bf16(
    bfloat16_t const* ptr, bfloat16x4x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
bfloat16x8x4_t vld4q_lane_bf16(
    bfloat16_t const* ptr, bfloat16x8x4_t src, const int lane);  // LD4 {Vt.h - Vt4.h}[lane],[Xn]
void vst2_lane_bf16(
    bfloat16_t* ptr, bfloat16x4x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst2q_lane_bf16(
    bfloat16_t* ptr, bfloat16x8x2_t val, const int lane);  // ST2 {Vt.h - Vt2.h}[lane],[Xn]
void vst3_lane_bf16(
    bfloat16_t* ptr, bfloat16x4x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst3q_lane_bf16(
    bfloat16_t* ptr, bfloat16x8x3_t val, const int lane);  // ST3 {Vt.h - Vt3.h}[lane],[Xn]
void vst4_lane_bf16(
    bfloat16_t* ptr, bfloat16x4x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst4q_lane_bf16(
    bfloat16_t* ptr, bfloat16x8x4_t val, const int lane);  // ST4 {Vt.h - Vt4.h}[lane],[Xn]
void vst1_bf16_x2(bfloat16_t* ptr, bfloat16x4x2_t val);    // ST1 {Vt.4H - Vt2.4H},[Xn]
void vst1q_bf16_x2(bfloat16_t* ptr, bfloat16x8x2_t val);   // ST1 {Vt.8H - Vt2.8H},[Xn]
void vst1_bf16_x3(bfloat16_t* ptr, bfloat16x4x3_t val);    // ST1 {Vt.4H - Vt3.4H},[Xn]
void vst1q_bf16_x3(bfloat16_t* ptr, bfloat16x8x3_t val);   // ST1 {Vt.8H - Vt3.8H},[Xn]
void vst1_bf16_x4(bfloat16_t* ptr, bfloat16x4x4_t val);    // ST1 {Vt.4H - Vt4.4H},[Xn]
void vst1q_bf16_x4(bfloat16_t* ptr, bfloat16x8x4_t val);   // ST1 {Vt.8H - Vt4.8H},[Xn]
bfloat16x4x2_t vld1_bf16_x2(bfloat16_t const* ptr);        // LD1 {Vt.4H - Vt2.4H},[Xn]
bfloat16x8x2_t vld1q_bf16_x2(bfloat16_t const* ptr);       // LD1 {Vt.8H - Vt2.8H},[Xn]
bfloat16x4x3_t vld1_bf16_x3(bfloat16_t const* ptr);        // LD1 {Vt.4H - Vt3.4H},[Xn]
bfloat16x8x3_t vld1q_bf16_x3(bfloat16_t const* ptr);       // LD1 {Vt.8H - Vt3.8H},[Xn]
bfloat16x4x4_t vld1_bf16_x4(bfloat16_t const* ptr);        // LD1 {Vt.4H - Vt4.4H},[Xn]
bfloat16x8x4_t vld1q_bf16_x4(bfloat16_t const* ptr);       // LD1 {Vt.8H - Vt4.8H},[Xn]
bfloat16x4_t vreinterpret_bf16_s8(int8x8_t a);             //
bfloat16x4_t vreinterpret_bf16_s16(int16x4_t a);           //
bfloat16x4_t vreinterpret_bf16_s32(int32x2_t a);           //
bfloat16x4_t vreinterpret_bf16_f32(float32x2_t a);         //
bfloat16x4_t vreinterpret_bf16_u8(uint8x8_t a);            //
bfloat16x4_t vreinterpret_bf16_u16(uint16x4_t a);          //
bfloat16x4_t vreinterpret_bf16_u32(uint32x2_t a);          //
bfloat16x4_t vreinterpret_bf16_p8(poly8x8_t a);            //
bfloat16x4_t vreinterpret_bf16_p16(poly16x4_t a);          //
bfloat16x4_t vreinterpret_bf16_u64(uint64x1_t a);          //
bfloat16x4_t vreinterpret_bf16_s64(int64x1_t a);           //
bfloat16x8_t vreinterpretq_bf16_s8(int8x16_t a);           //
bfloat16x8_t vreinterpretq_bf16_s16(int16x8_t a);          //
bfloat16x8_t vreinterpretq_bf16_s32(int32x4_t a);          //
bfloat16x8_t vreinterpretq_bf16_f32(float32x4_t a);        //
bfloat16x8_t vreinterpretq_bf16_u8(uint8x16_t a);          //
bfloat16x8_t vreinterpretq_bf16_u16(uint16x8_t a);         //
bfloat16x8_t vreinterpretq_bf16_u32(uint32x4_t a);         //
bfloat16x8_t vreinterpretq_bf16_p8(poly8x16_t a);          //
bfloat16x8_t vreinterpretq_bf16_p16(poly16x8_t a);         //
bfloat16x8_t vreinterpretq_bf16_u64(uint64x2_t a);         //
bfloat16x8_t vreinterpretq_bf16_s64(int64x2_t a);          //
bfloat16x4_t vreinterpret_bf16_f64(float64x1_t a);         //
bfloat16x8_t vreinterpretq_bf16_f64(float64x2_t a);        //
bfloat16x4_t vreinterpret_bf16_p64(poly64x1_t a);          //
bfloat16x8_t vreinterpretq_bf16_p64(poly64x2_t a);         //
bfloat16x8_t vreinterpretq_bf16_p128(poly128_t a);         //
int8x8_t vreinterpret_s8_bf16(bfloat16x4_t a);             //
int16x4_t vreinterpret_s16_bf16(bfloat16x4_t a);           //
int32x2_t vreinterpret_s32_bf16(bfloat16x4_t a);           //
float32x2_t vreinterpret_f32_bf16(bfloat16x4_t a);         //
uint8x8_t vreinterpret_u8_bf16(bfloat16x4_t a);            //
uint16x4_t vreinterpret_u16_bf16(bfloat16x4_t a);          //
uint32x2_t vreinterpret_u32_bf16(bfloat16x4_t a);          //
poly8x8_t vreinterpret_p8_bf16(bfloat16x4_t a);            //
poly16x4_t vreinterpret_p16_bf16(bfloat16x4_t a);          //
uint64x1_t vreinterpret_u64_bf16(bfloat16x4_t a);          //
int64x1_t vreinterpret_s64_bf16(bfloat16x4_t a);           //
float64x1_t vreinterpret_f64_bf16(bfloat16x4_t a);         //
poly64x1_t vreinterpret_p64_bf16(bfloat16x4_t a);          //
int8x16_t vreinterpretq_s8_bf16(bfloat16x8_t a);           //
int16x8_t vreinterpretq_s16_bf16(bfloat16x8_t a);          //
int32x4_t vreinterpretq_s32_bf16(bfloat16x8_t a);          //
float32x4_t vreinterpretq_f32_bf16(bfloat16x8_t a);        //
uint8x16_t vreinterpretq_u8_bf16(bfloat16x8_t a);          //
uint16x8_t vreinterpretq_u16_bf16(bfloat16x8_t a);         //
uint32x4_t vreinterpretq_u32_bf16(bfloat16x8_t a);         //
poly8x16_t vreinterpretq_p8_bf16(bfloat16x8_t a);          //
poly16x8_t vreinterpretq_p16_bf16(bfloat16x8_t a);         //
uint64x2_t vreinterpretq_u64_bf16(bfloat16x8_t a);         //
int64x2_t vreinterpretq_s64_bf16(bfloat16x8_t a);          //
float64x2_t vreinterpretq_f64_bf16(bfloat16x8_t a);        //
poly64x2_t vreinterpretq_p64_bf16(bfloat16x8_t a);         //
poly128_t vreinterpretq_p128_bf16(bfloat16x8_t a);         //
float32x4_t vcvt_f32_bf16(bfloat16x4_t a);                 // SHLL Vd.4S,Vn.8H,#16
float32x4_t vcvtq_low_f32_bf16(bfloat16x8_t a);            // SHLL Vd.4S,Vn.8H,#16
float32x4_t vcvtq_high_f32_bf16(bfloat16x8_t a);           // SHLL2 Vd.4S,Vn.8H,#16
bfloat16x4_t vcvt_bf16_f32(float32x4_t a);                 // BFCVTN Vd.4H,Vn.4S
bfloat16x8_t vcvtq_low_bf16_f32(float32x4_t a);            // BFCVTN Vd.4H,Vn.4S
bfloat16x8_t vcvtq_high_bf16_f32(bfloat16x8_t inactive, float32x4_t a);  // BFCVTN2 Vd.8H,Vn.4S
bfloat16_t vcvth_bf16_f32(float32_t a);                                  // BFCVT Hd,Sn
float32_t vcvtah_f32_bf16(bfloat16_t a);                                 // SHL Dd,Dn,#16
bfloat16x4_t vcopy_lane_bf16(bfloat16x4_t a, const int lane1, bfloat16x4_t b,
    const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
bfloat16x8_t vcopyq_lane_bf16(bfloat16x8_t a, const int lane1, bfloat16x4_t b,
    const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
bfloat16x4_t vcopy_laneq_bf16(bfloat16x4_t a, const int lane1, bfloat16x8_t b,
    const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
bfloat16x8_t vcopyq_laneq_bf16(bfloat16x8_t a, const int lane1, bfloat16x8_t b,
    const int lane2);  // INS Vd.H[lane1],Vn.H[lane2]
float32x2_t vbfdot_f32(float32x2_t r, bfloat16x4_t a, bfloat16x4_t b);   // BFDOT Vd.2S,Vn.4H,Vm.4H
float32x4_t vbfdotq_f32(float32x4_t r, bfloat16x8_t a, bfloat16x8_t b);  // BFDOT Vd.4S,Vn.8H,Vm.8H
float32x2_t vbfdot_lane_f32(float32x2_t r, bfloat16x4_t a, bfloat16x4_t b,
    const int lane);  // BFDOT Vd.2S,Vn.4H,Vm.2H[lane]
float32x4_t vbfdotq_laneq_f32(float32x4_t r, bfloat16x8_t a, bfloat16x8_t b,
    const int lane);  // BFDOT Vd.4S,Vn.8H,Vm.2H[lane]
float32x2_t vbfdot_laneq_f32(float32x2_t r, bfloat16x4_t a, bfloat16x8_t b,
    const int lane);  // BFDOT Vd.2S,Vn.4H,Vm.2H[lane]
float32x4_t vbfdotq_lane_f32(float32x4_t r, bfloat16x8_t a, bfloat16x4_t b,
    const int lane);  // BFDOT Vd.4S,Vn.8H,Vm.2H[lane]
float32x4_t vbfmmlaq_f32(
    float32x4_t r, bfloat16x8_t a, bfloat16x8_t b);  // BFMMLA Vd.4S,Vn.8H,Vm.8H
float32x4_t vbfmlalbq_f32(
    float32x4_t r, bfloat16x8_t a, bfloat16x8_t b);  // BFMLALB Vd.4S,Vn.8H,Vm.8H
float32x4_t vbfmlaltq_f32(
    float32x4_t r, bfloat16x8_t a, bfloat16x8_t b);  // BFMLALT Vd.4S,Vn.8H,Vm.8H
float32x4_t vbfmlalbq_lane_f32(float32x4_t r, bfloat16x8_t a, bfloat16x4_t b,
    const int lane);  // BFMLALB Vd.4S,Vn.8H,Vm.H[lane]
float32x4_t vbfmlalbq_laneq_f32(float32x4_t r, bfloat16x8_t a, bfloat16x8_t b,
    const int lane);  // BFMLALB Vd.4S,Vn.8H,Vm.H[lane]
float32x4_t vbfmlaltq_lane_f32(float32x4_t r, bfloat16x8_t a, bfloat16x4_t b,
    const int lane);  // BFMLALT Vd.4S,Vn.8H,Vm.H[lane]
float32x4_t vbfmlaltq_laneq_f32(float32x4_t r, bfloat16x8_t a, bfloat16x8_t b,
    const int lane);  // BFMLALT Vd.4S,Vn.8H,Vm.H[lane]
