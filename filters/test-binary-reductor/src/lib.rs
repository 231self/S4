//! Test-only component used to verify the binary reductor host ABI.

#[cfg(target_arch = "wasm32")]
mod guest {
    wit_bindgen::generate!({
        world: "binary-reductor",
        path: "../../wit/s4-binary-reductor/world.wit",
    });

    struct TestBinaryReductor;

    const CUSTOM_SCHEMA_IR: &[u8] = br#"{"root":{"kind":{"type":"custom","type_id":"vendor.money","value":{"kind":{"type":"string"},"nullable":false}},"nullable":false},"version":1}"#;
    const STRING_SCHEMA_IR: &[u8] =
        br#"{"root":{"kind":{"type":"string"},"nullable":false},"version":1}"#;
    const CUSTOM_VALUE_IR: &[u8] = br#"{"root":{"type":"custom","type_id":"vendor.money","value":{"type":"string","value":"12.34"}},"version":1}"#;
    const STRING_VALUE_IR: &[u8] = br#"{"root":{"type":"string","value":"12.34"},"version":1}"#;
    const REDUCTION_PLAN: &[u8] = b"vendor.money->string@1";
    const RESTORATION_PLAN_PREFIX: &[u8] = b"vendor.money<-";

    fn restoration_plan(schema_ir: &[u8]) -> Vec<u8> {
        let mut plan = RESTORATION_PLAN_PREFIX.to_vec();
        plan.extend_from_slice(schema_ir);
        plan
    }

    impl Guest for TestBinaryReductor {
        fn plan(source_schema_ir: Vec<u8>) -> Result<PlannedReduction, ReductorError> {
            if source_schema_ir == b"e" {
                return Err(ReductorError {
                    code: "test.invalid-schema".to_string(),
                    message: "schema was rejected".to_string(),
                });
            }
            if source_schema_ir == CUSTOM_SCHEMA_IR {
                return Ok(PlannedReduction {
                    claims: vec![Claim {
                        path: Vec::new(),
                        type_id: "vendor.money".to_string(),
                    }],
                    reduced_schema_ir: STRING_SCHEMA_IR.to_vec(),
                    plan: REDUCTION_PLAN.to_vec(),
                });
            }
            let reduced_schema_ir = if source_schema_ir == b"s" {
                vec![0; 9]
            } else {
                source_schema_ir
            };
            let plan = if reduced_schema_ir == b"p" {
                vec![0; 9]
            } else {
                Vec::new()
            };
            Ok(PlannedReduction {
                claims: vec![Claim {
                    path: vec![PathSegment::Field("custom".to_string())],
                    type_id: "test.custom".to_string(),
                }],
                reduced_schema_ir,
                plan,
            })
        }

        fn plan_restore(
            source_schema_ir: Vec<u8>,
            transformed_reduced_schema_ir: Vec<u8>,
            plan: Vec<u8>,
        ) -> Result<PlannedRestoration, ReductorError> {
            if source_schema_ir == CUSTOM_SCHEMA_IR
                && transformed_reduced_schema_ir == STRING_SCHEMA_IR
                && plan == REDUCTION_PLAN
            {
                return Ok(PlannedRestoration {
                    output_schema_ir: CUSTOM_SCHEMA_IR.to_vec(),
                    restore_plan: restoration_plan(&transformed_reduced_schema_ir),
                });
            }
            if transformed_reduced_schema_ir == b"x" {
                Ok(PlannedRestoration {
                    output_schema_ir: vec![0; 9],
                    restore_plan: Vec::new(),
                })
            } else if transformed_reduced_schema_ir == b"r" {
                Ok(PlannedRestoration {
                    output_schema_ir: transformed_reduced_schema_ir,
                    restore_plan: vec![0; 9],
                })
            } else {
                Ok(PlannedRestoration {
                    output_schema_ir: transformed_reduced_schema_ir,
                    restore_plan: Vec::new(),
                })
            }
        }

        fn reduce(plan: Vec<u8>, source_value_ir: Vec<u8>) -> Result<Vec<u8>, ReductorError> {
            if source_value_ir == b"loop" {
                loop {
                    std::hint::black_box(());
                }
            }
            if plan == REDUCTION_PLAN && source_value_ir == CUSTOM_VALUE_IR {
                return Ok(STRING_VALUE_IR.to_vec());
            }
            if source_value_ir == b"x" {
                Ok(vec![0; 9])
            } else {
                Ok(source_value_ir)
            }
        }

        fn restore(
            restore_plan: Vec<u8>,
            transformed_value_ir: Vec<u8>,
        ) -> Result<Vec<u8>, ReductorError> {
            if restore_plan == restoration_plan(STRING_SCHEMA_IR)
                && transformed_value_ir == STRING_VALUE_IR
            {
                return Ok(CUSTOM_VALUE_IR.to_vec());
            }
            if transformed_value_ir == b"x" {
                Ok(vec![0; 9])
            } else {
                Ok(transformed_value_ir)
            }
        }
    }

    export!(TestBinaryReductor);
}
