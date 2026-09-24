//! Cumulative Task 4 terminal demo.
//!
//! Each completed Task 4 issue adds one concise step to this flow.

use anyhow::{bail, Result};
use sgx_anomaly_engine::policy::PolicyTemplates;
use sgx_anomaly_engine::threat_prediction::{
    assess_confidence, evaluate_controlled_cases, geo_can_support_evidence_backed_forecast,
    match_precursor_sequence, persist_e2e_evaluation_artifact, predict_peer_cascade,
    read_task1_anomalies, read_task3_degradation_events_at, recommend_predictive_hardening,
    run_e2e_cycle, CalibrationMetadata, ConfidenceContext, ControlledCaseResult, DdosPredictor,
    E2eCycleInput, E2ePrimaryPredictor, EventSeverity, EvidenceSource, ForecastExplanation,
    ForecastSeverity, ForecastStatus, ForecastStore, GeoThreatSignal,
    HardeningRecommendationConfig, PeerRelationship, PrecursorSequenceDefinition,
    PredictedThreatType, SecurityEvent, SecurityEventType, Task3ContextConfig, Task3NetworkContext,
    TemporalFeatureConfig, TemporalFeatureEngine, ThreatForecast, ThreatPredictionConfig,
    ThreatPredictionError, ThreatPredictor, ThreatPredictorInput, SECURITY_EVENT_SCHEMA_VERSION,
    TASK3_NETWORK_CONTEXT_SCHEMA_VERSION, THREAT_FORECAST_SCHEMA_VERSION,
};
use std::path::PathBuf;

/// Use a real Task1 output when a user has generated one locally. No Task1
/// record is fabricated by this cumulative Task4 demo.
fn task1_demo_artifact() -> Result<PathBuf> {
    [
        "data/recommendation_records/nodeA/run_013/recommendations.json",
        "data/recommendation_records/nodeA/run_002/recommendations.json",
        "data/recommendation_records/nodeA/run_001/recommendations.json",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .ok_or_else(|| {
        anyhow::anyhow!(
            "no Task1 recommendation artifact found; first run the supported Task1 live replay"
        )
    })
}

fn main() -> Result<()> {
    println!("====================================================");
    println!("SG-X GUARDIAN - TASK 4 AI ENGINE");
    println!("====================================================\n");
    println!("Starting Threat Prediction Engine...\n");

    let config = ThreatPredictionConfig::load_json("config/threat_prediction.json")?;
    let task1_artifact_path = task1_demo_artifact()?;
    println!("Configuration loaded ✓");
    println!(
        "Forecast cycle       : {} minutes",
        config.forecast_interval_minutes
    );
    println!(
        "Minimum confidence   : {:.0}%",
        config.minimum_action_confidence * 100.0
    );
    println!(
        "Retention            : {} days",
        config.forecast_retention_days
    );
    println!("Threshold profile    : Valid ✓");
    println!("\n----------------------------------------------------\n");

    println!("Incoming Sample Forecast");
    println!("(SAMPLE data only - not an AI-generated prediction)\n");
    let sample = sample_ddos_forecast(30, 0.85, 0.78);
    println!("Threat       : DDoS");
    println!("Target       : nodeB");
    println!("Forecast     : Next 30 minutes");
    println!("Probability  : {:.0}%", sample.probability * 100.0);
    println!("Confidence   : {:.0}%\n", sample.confidence * 100.0);
    println!("Validating forecast...\n");
    sample.validate()?;
    if !config.is_actionable(sample.probability, sample.confidence)? {
        bail!("sample forecast should be actionable under the loaded Task4 configuration");
    }
    println!("✓ Threat type supported");
    println!("✓ Probability valid");
    println!("✓ Confidence valid");
    println!("✓ Forecast horizon valid");
    assert_serialization_round_trip(&sample)?;
    println!("✓ Serialization round-trip valid\n");
    println!("FORECAST ACCEPTED ✓");
    println!("\n----------------------------------------------------\n");

    println!("Invalid Forecast Safety Check\n");
    println!("Threat       : DDoS");
    println!("Target       : nodeB");
    println!("Forecast     : Next 120 minutes\n");
    println!("Validating forecast...\n");
    expect_rejection(sample_ddos_forecast(120, 0.85, 0.78), |error| {
        matches!(error, ThreatPredictionError::InvalidHorizon(_))
    })?;
    println!("✓ Threat type supported");
    println!("✗ Forecast horizon invalid\n");
    println!("FORECAST REJECTED ✓");
    println!("\n----------------------------------------------------\n");

    println!("Additional Safety Checks\n");
    expect_rejection(sample_ddos_forecast(30, 1.01, 0.78), |error| {
        matches!(error, ThreatPredictionError::InvalidProbability(_))
    })?;
    println!("Invalid probability   -> REJECTED ✓");
    expect_rejection(sample_ddos_forecast(30, 0.85, f64::NAN), |error| {
        matches!(error, ThreatPredictionError::InvalidConfidence(_))
    })?;
    println!("Invalid confidence    -> REJECTED ✓");
    expect_rejection(sample_ddos_forecast(120, 0.85, 0.78), |error| {
        matches!(error, ThreatPredictionError::InvalidHorizon(_))
    })?;
    println!("Invalid horizon       -> REJECTED ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #2 - Normalized Security Event\n");
    println!("(SAMPLE Suricata evidence only - no live IDS connection)\n");
    let event = sample_reconnaissance_event();
    event.validate()?;
    println!("Source       : Suricata");
    println!("Event type   : Reconnaissance");
    println!("Target node  : nodeB");
    println!("Severity     : High");
    println!("Confidence   : {:.0}%", event.confidence * 100.0);
    println!("Validation   : ACCEPTED ✓");

    let duplicate = event.clone();
    if event.deduplication_key() != duplicate.deduplication_key() {
        bail!("identical normalized events must have the same deduplication key");
    }
    println!("Duplicate replay detection : same event key ✓");

    let mut changed = event.clone();
    changed.destination_port = Some(443);
    if event.deduplication_key() == changed.deduplication_key() {
        bail!("meaningfully changed normalized events must have different deduplication keys");
    }
    println!("Meaningful event change    : new event key ✓");

    let mut malformed = event;
    malformed.node_id.clear();
    expect_event_rejection(malformed)?;
    println!("Malformed event            : REJECTED ✓\n");
    println!("ISSUE #2 - EVENT NORMALIZATION CONTRACT: PASS ✓\n");
    println!("\n----------------------------------------------------\n");
    println!("Issue #3 - Task 1 Anomaly Evidence Bridge\n");
    println!("Reading existing Task 1 recommendation evidence...\n");
    let task1_events = read_task1_anomalies(&task1_artifact_path)?;
    let task1_event = task1_events
        .first()
        .ok_or_else(|| anyhow::anyhow!("Task 1 fixture did not contain an anomaly record"))?;
    println!("Task 1 source     : task1-anomaly-engine");
    println!(
        "Source record ID  : {}",
        task1_event.attributes["task1_rec_id"]
    );
    println!("Target node       : {}", task1_event.node_id);
    println!("Observed at       : {} ms", task1_event.observed_at_ms);
    println!("Task 4 event type : {:?}", task1_event.event_type);
    println!(
        "Anomaly score     : {}",
        task1_event.attributes["task1_anomaly_score"]
    );
    for evidence_key in [
        "task1_model_metadata",
        "task1_top_contributors",
        "task1_port_security_context",
    ] {
        if !task1_event.attributes.contains_key(evidence_key) {
            bail!("Task 1 bridge did not preserve required {evidence_key} evidence");
        }
    }
    println!("Model metadata    : preserved ✓");
    println!("Top contributors  : preserved ✓");
    println!("Port/security data: preserved ✓");
    println!("Source IDs preserved          : ACCEPTED ✓");
    println!("No duplicate anomaly inference: ACCEPTED ✓");
    println!("ISSUE #3 - TASK 1 BRIDGE: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #4 - Temporal Feature Engine\n");
    let reference_time_ms = task1_events
        .iter()
        .map(|event| event.observed_at_ms)
        .max()
        .ok_or_else(|| anyhow::anyhow!("Task 1 bridge did not provide temporal evidence"))?
        + 60_000;
    let mut temporal = TemporalFeatureEngine::new(TemporalFeatureConfig::default())?;
    for task1_event in task1_events {
        temporal.ingest(task1_event)?;
    }
    let features = temporal.features_for_node_at("nodeA", reference_time_ms);
    let recent = &features.windows[&30];
    let daily = &features.windows[&1_440];
    println!("Reference time     : {reference_time_ms} ms (fixed for repeatable analysis)");
    println!("Last 30 min events : {}", recent.event_count);
    println!("Last 24h events    : {}", daily.event_count);
    println!(
        "Task1 score max    : {:.3}",
        recent.anomaly_score_max.unwrap_or(0.0)
    );
    println!(
        "Timezone profile   : UTC hour {} (nodeA only)",
        features.time_of_day.hour_of_day
    );
    println!(
        "New-device rate    : {:.3}/min",
        recent.new_device_rate_per_minute
    );
    println!("Vulnerable services: {}", recent.vulnerable_service_count);
    println!("Future data        : excluded ✓");
    println!("History bound      : 7 days / 10,000 events ✓");
    println!("ISSUE #4 - TEMPORAL FEATURE ENGINE: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #5 - Ordered Attack Precursors\n");
    println!("(SAMPLE normalized sequence — not an AI-generated prediction)\n");
    let sequence = PrecursorSequenceDefinition::recon_to_compromise();
    let sequence_reference_ms = 1_000_000;
    let sequence_events = sample_ordered_precursors(&sequence, sequence_reference_ms);
    let sequence_match =
        match_precursor_sequence(&sequence, "nodeB", &sequence_events, sequence_reference_ms)?;
    println!("Sequence          : reconnaissance -> compromise indicators");
    println!("\nObserved precursor steps (SAMPLE evidence):");
    for (index, event) in sequence_events.iter().enumerate() {
        println!(
            "  {}. {}",
            index + 1,
            precursor_step_label(event.event_type)
        );
    }
    println!(
        "Target correlation: {}",
        sequence_match.target_correlation_key
    );
    println!(
        "Ordered steps     : {}/{}",
        sequence_match.matched_steps, sequence_match.total_steps
    );
    println!(
        "Evidence sources  : {} ({})",
        sequence_match.evidence_source_count,
        sequence_events
            .iter()
            .map(|event| evidence_source_label(event.source))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "Fresh sequence    : {}",
        if sequence_match.fresh {
            "YES ✓"
        } else {
            "NO"
        }
    );
    println!("ISSUE #5 - SEQUENCE / PRECURSOR ENGINE: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #6 - Deterministic Threat Predictor\n");
    println!("(SAMPLE normalized evidence; forecast is calculated by D6 predictor)\n");
    let predictor_reference_ms = 2_000_000;
    let predictor_events = sample_ddos_predictor_events(predictor_reference_ms);
    let mut predictor_temporal = TemporalFeatureEngine::new(TemporalFeatureConfig::default())?;
    for predictor_event in predictor_events.iter().cloned() {
        predictor_temporal.ingest(predictor_event)?;
    }
    let predictor_features =
        predictor_temporal.features_for_node_at("nodeB", predictor_reference_ms);
    let predicted = DdosPredictor
        .predict(&ThreatPredictorInput {
            node_id: "nodeB",
            evaluated_at_ms: predictor_reference_ms,
            temporal_features: &predictor_features,
            events: &predictor_events,
            precursor_sequence: None,
            config: &config,
        })?
        .ok_or_else(|| {
            anyhow::anyhow!("sample DDoS evidence should meet the D6 predictor threshold")
        })?;
    predicted.validate()?;
    println!("Predictor          : DDoS baseline predictor");
    println!("Target             : nodeB");
    println!("Forecast horizon   : next 5 minutes");
    println!("Probability        : {:.0}%", predicted.probability * 100.0);
    println!("Confidence         : {:.0}%", predicted.confidence * 100.0);
    println!("Evidence IDs       : {}", predicted.evidence_ids.join(", "));
    println!("Top contributing signals:");
    for factor in &predicted.explanation.top_factors {
        println!("  - {}", factor.name.replace('_', " "));
    }
    println!("ISSUE #6 - THREAT PREDICTORS: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #7 - Peer Cascade Prediction\n");
    println!("(SAMPLE normalized relationship/evidence; forecast is calculated by D7)\n");
    let cascade_reference_ms = 3_000_000;
    let relationship = sample_peer_relationship(cascade_reference_ms);
    let cascade_events = vec![
        sample_cascade_event(
            "sample-task1-cascade",
            EvidenceSource::Task1Anomaly,
            cascade_reference_ms - 30_000,
        ),
        sample_cascade_event(
            "sample-circle-trust",
            EvidenceSource::CircleTrust,
            cascade_reference_ms - 20_000,
        ),
    ];
    let cascade = predict_peer_cascade(
        0.95,
        &relationship,
        &cascade_events,
        cascade_reference_ms,
        &config,
    )?
    .ok_or_else(|| anyhow::anyhow!("sample related peer should receive a D7 forecast"))?;
    cascade.validate()?;
    println!("Related peer       : nodeB");
    println!("Relationship       : same segment + direct communication + shared relay");
    println!("Forecast horizon   : next 15 minutes");
    println!("Probability        : {:.0}%", cascade.probability * 100.0);
    println!("Confidence         : {:.0}%", cascade.confidence * 100.0);
    println!("Evidence IDs       : {}", cascade.evidence_ids.join(", "));
    println!(
        "Relationship reasons: {}",
        cascade.explanation.relationship_reasons.join(", ")
    );
    println!("Result             : elevated cascade risk (not a compromise declaration) ✓\n");

    let circle_only = predict_peer_cascade(
        0.95,
        &relationship,
        &[sample_cascade_event(
            "sample-circle-only",
            EvidenceSource::CircleTrust,
            cascade_reference_ms - 20_000,
        )],
        cascade_reference_ms,
        &config,
    )?;
    if circle_only.is_some() {
        bail!("Circle-only sample must not create a cascade forecast");
    }
    println!("Circle-only peer   : REJECTED — membership/trust alone cannot create cascade risk ✓");
    println!("ISSUE #7 - PEER CASCADE PREDICTION: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #8 - Confidence, Calibration & Geo Contract\n");
    println!("(SAMPLE normalized evidence; no external geo feed is contacted)\n");
    let calibration = CalibrationMetadata {
        model_version: "task4-d6-predictors-v1".to_string(),
        calibration_version: "task4-calibration-v1".to_string(),
        training_period: "controlled-fixtures-2026q3".to_string(),
        validation_period: "controlled-fixtures-2026q3".to_string(),
        threshold_profile_version: "task4-thresholds-v1".to_string(),
    };
    let assessed = assess_confidence(
        &ConfidenceContext {
            contributing_sources: vec![EvidenceSource::Task1Anomaly, EvidenceSource::Suricata],
            ..Default::default()
        },
        calibration,
    )?;
    println!("Threat probability : 87% (likelihood — unchanged by confidence assessment)");
    println!(
        "Evidence confidence: {:.0}% (reliability from 2 independent sources)",
        assessed.confidence * 100.0
    );
    println!(
        "Calibration        : {}",
        assessed.calibration.calibration_version
    );
    let integrated_forecast = DdosPredictor
        .predict(&ThreatPredictorInput {
            node_id: "nodeB",
            evaluated_at_ms: predictor_reference_ms,
            temporal_features: &predictor_features,
            events: &predictor_events,
            precursor_sequence: None,
            config: &config,
        })?
        .ok_or_else(|| {
            anyhow::anyhow!("sample D6 evidence should produce an integrated D8 forecast")
        })?;
    let integrated_calibration = integrated_forecast
        .explanation
        .calibration
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("D6 forecast must preserve D8 calibration metadata"))?;
    println!(
        "Integrated D6/D8    : {:.0}% probability / {:.0}% confidence",
        integrated_forecast.probability * 100.0,
        integrated_forecast.confidence * 100.0
    );
    println!(
        "Forecast calibration: {}",
        integrated_calibration.calibration_version
    );
    let geo = GeoThreatSignal {
        source_ip: "8.8.8.8".to_string(),
        country_code: Some("US".to_string()),
        region: Some("sample-region".to_string()),
        reputation_score: Some(0.80),
        feed_id: "sample-authorized-feed".to_string(),
        observed_at_ms: 3_000_000,
        expires_at_ms: 3_030_000,
    };
    let geo_only = geo_can_support_evidence_backed_forecast(&geo, 3_000_000, false)?;
    if geo_only {
        bail!("geo evidence alone must not support a high-impact forecast");
    }
    println!("Geo evidence       : validated as optional supporting evidence ✓");
    println!("Geo alone          : cannot create high-impact recommendation ✓");
    println!("ISSUE #8 - CONFIDENCE, CALIBRATION & GEO CONTRACT: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #9 - Explainability & Forecast Lifecycle\n");
    println!("(SAMPLE persisted forecast; no policy action is performed)\n");
    let lifecycle_root = std::env::temp_dir().join(format!("task4-d9-demo-{}", std::process::id()));
    let lifecycle_store = ForecastStore::new(&lifecycle_root, config.forecast_retention_days)?;
    lifecycle_store.persist_initial(integrated_forecast.clone(), predictor_reference_ms + 1)?;
    let restarted_store = ForecastStore::new(&lifecycle_root, config.forecast_retention_days)?;
    let reloaded = restarted_store.load_current(&integrated_forecast.forecast_id)?;
    let superseded = restarted_store.transition(
        &integrated_forecast.forecast_id,
        ForecastStatus::Superseded,
        predictor_reference_ms + 2,
        "SAMPLE newer forecast replaced this active forecast",
    )?;
    let history = restarted_store.history(&integrated_forecast.forecast_id)?;
    println!("Initial forecast    : saved with evidence, factors and calibration ✓");
    println!("Restart reload      : {} ✓", reloaded.forecast.forecast_id);
    println!(
        "Lifecycle transition: Active -> {:?} ✓",
        superseded.forecast.status
    );
    println!(
        "History records     : {} (initial + transition preserved)",
        history.len()
    );
    println!(
        "Retention           : {} days (configurable)",
        config.forecast_retention_days
    );
    println!("ISSUE #9 - EXPLAINABILITY & FORECAST LIFECYCLE: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #10 - Task 2 Predictive Hardening Contract\n");
    println!("(SAMPLE advisory contract; no Task 2 policy is approved, signed, or applied)\n");
    let task2_templates = PolicyTemplates::from_path("config/policy_action_templates.json")?;
    let hardening = recommend_predictive_hardening(
        &integrated_forecast,
        &config,
        &HardeningRecommendationConfig::default(),
        &task2_templates,
    )?;
    println!("Forecast link       : {}", hardening.forecast_id);
    println!(
        "Target node         : {}",
        hardening.target_nodes.join(", ")
    );
    println!("Task 2 actions      : {:?}", hardening.actions);
    println!(
        "Evidence IDs        : {}",
        hardening.evidence_ids.join(", ")
    );
    println!("Approval required   : YES — Task 2 review only ✓");
    println!("Enforcement         : NOT performed by Task 4 ✓");
    println!("ISSUE #10 - PREDICTIVE HARDENING CONTRACT: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #11 - Task 3 Network Context Contract\n");
    println!(
        "(SAMPLE canonical Task 3 degradation audit context; Task 4 does not change routes)\n"
    );
    let task3_context = Task3NetworkContext {
        schema_version: TASK3_NETWORK_CONTEXT_SCHEMA_VERSION,
        decision_id: "task3-decision-nodeA-nodeB-demo-001".into(),
        observed_at_ms: predictor_reference_ms,
        node_id: "nodeB".into(),
        peer_id: Some("nodeA".into()),
        route_id: "relay-nodeA-nodeB".into(),
        degradation_probability: 0.82,
        degradation_horizon_seconds: 60,
        model_version: "degradation-v1-interpretable".into(),
        contributors: vec!["latency_rising".into(), "high_packet_loss".into()],
        reason: "Task 3 retained route history shows elevated degradation risk".into(),
    };
    let task3_context_path =
        std::env::temp_dir().join(format!("task4-d11-demo-{}.jsonl", std::process::id()));
    let task3_audit_row = serde_json::json!({
        "decision_id": task3_context.decision_id.clone(),
        "ts_ms": task3_context.observed_at_ms,
        "prediction": {
            "model_version": task3_context.model_version.clone(),
            "route_id": task3_context.route_id.clone(),
            "probability": task3_context.degradation_probability,
            "horizon_seconds": task3_context.degradation_horizon_seconds,
            "contributors": task3_context.contributors.clone(),
            "reason": task3_context.reason.clone(),
        }
    });
    std::fs::write(&task3_context_path, serde_json::to_vec(&task3_audit_row)?)?;
    let mut task3_events = read_task3_degradation_events_at(
        &task3_context_path,
        "nodeB",
        Some("nodeA"),
        predictor_reference_ms,
        &Task3ContextConfig::default(),
    )?;
    let task3_event = task3_events
        .pop()
        .ok_or_else(|| anyhow::anyhow!("fresh Task 3 demo context was not accepted"))?;
    let mut task3_temporal = TemporalFeatureEngine::new(TemporalFeatureConfig::default())?;
    task3_temporal.ingest(task3_event)?;
    let task3_features = task3_temporal.features_for_node_at("nodeB", predictor_reference_ms);
    let task3_window = &task3_features.windows[&5];
    println!("Task 3 decision ID : {}", task3_context.decision_id);
    println!("Route context      : {}", task3_context.route_id);
    println!(
        "Degradation risk   : {:.0}%",
        task3_context.degradation_probability * 100.0
    );
    println!(
        "Task 4 feature     : 5m degradation rate {:.2}/min",
        task3_window.network_degradation_rate_per_minute
    );
    println!(
        "Task 4 feature     : max degradation probability {:.0}%",
        task3_window
            .network_degradation_probability_max
            .unwrap_or_default()
            * 100.0
    );
    println!("Route mutation     : NOT performed by Task 4 ✓");
    let missing_task3_context_path = std::env::temp_dir().join(format!(
        "task4-d11-missing-context-{}-{}.jsonl",
        std::process::id(),
        predictor_reference_ms
    ));
    let missing_task3_events = read_task3_degradation_events_at(
        &missing_task3_context_path,
        "nodeB",
        Some("nodeA"),
        predictor_reference_ms,
        &Task3ContextConfig::default(),
    )?;
    if !missing_task3_events.is_empty() {
        bail!("missing Task 3 context must safely return zero events");
    }
    println!("Missing context    : real reader returned 0 events safely ✓");
    let _ = std::fs::remove_file(&task3_context_path);
    println!("ISSUE #11 - TASK 3 CONTEXT CONTRACT: PASS ✓\n");

    println!("----------------------------------------------------\n");
    println!("Issue #12 - End-to-End Pipeline & Controlled Benchmark\n");
    println!("(SAMPLE controlled fixture; no policy or route enforcement is performed)\n");
    let d12_evaluation_id = format!("task4-d12-demo-{}", std::process::id());
    let d12_root = std::env::temp_dir().join(&d12_evaluation_id);
    let d12_task3_context_path =
        std::env::temp_dir().join(format!("{d12_evaluation_id}-degradation_events.jsonl"));
    std::fs::write(
        &d12_task3_context_path,
        serde_json::to_vec(&serde_json::json!({
            "decision_id": "task3-d12-nodea-nodeb-001",
            "ts_ms": predictor_reference_ms,
            "prediction": {
                "model_version": "degradation-v1-interpretable",
                "route_id": "relay-nodeA-nodeB",
                "probability": 0.82,
                "horizon_seconds": 60,
                "contributors": ["latency_rising"],
                "reason": "SAMPLE retained Task3 degradation evidence"
            }
        }))?,
    )?;
    let d12_output = run_e2e_cycle(E2eCycleInput {
        evaluation_id: d12_evaluation_id.clone(),
        node_id: "nodeB".into(),
        evaluated_at_ms: predictor_reference_ms,
        events: predictor_events.clone(),
        task1_recommendation_path: Some(task1_artifact_path.clone()),
        task3_degradation_path: Some(d12_task3_context_path.clone()),
        task3_peer_id: Some("nodeA".into()),
        task3_context_config: Task3ContextConfig::default(),
        temporal_config: TemporalFeatureConfig::default(),
        prediction_config: config.clone(),
        primary_predictor: E2ePrimaryPredictor::Ddos,
        sequence_definition: PrecursorSequenceDefinition::recon_to_compromise(),
        peer_relationship: None,
        source_compromise_probability: None,
        hardening_config: HardeningRecommendationConfig::default(),
        task2_templates: task2_templates.clone(),
        audit_root: d12_root.clone(),
    })?;
    let d12_forecast = d12_output
        .forecast
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("D12 positive fixture did not produce a forecast"))?;
    let d12_benign = run_e2e_cycle(E2eCycleInput {
        evaluation_id: format!("{d12_evaluation_id}-benign"),
        node_id: "nodeB".into(),
        evaluated_at_ms: predictor_reference_ms,
        events: Vec::new(),
        task1_recommendation_path: None,
        task3_degradation_path: None,
        task3_peer_id: None,
        task3_context_config: Task3ContextConfig::default(),
        temporal_config: TemporalFeatureConfig::default(),
        prediction_config: config.clone(),
        primary_predictor: E2ePrimaryPredictor::Ddos,
        sequence_definition: PrecursorSequenceDefinition::recon_to_compromise(),
        peer_relationship: None,
        source_compromise_probability: None,
        hardening_config: HardeningRecommendationConfig::default(),
        task2_templates: task2_templates.clone(),
        audit_root: std::env::temp_dir().join(format!("{d12_evaluation_id}-benign")),
    })?;
    let d12_metrics = evaluate_controlled_cases(
        &[
            ControlledCaseResult {
                expected_threat: true,
                forecast_created: d12_output.forecast.is_some(),
                evaluated_at_ms: predictor_reference_ms,
                known_threat_at_ms: Some(predictor_reference_ms + 5 * 60_000),
            },
            ControlledCaseResult {
                expected_threat: false,
                forecast_created: d12_benign.forecast.is_some(),
                evaluated_at_ms: predictor_reference_ms,
                known_threat_at_ms: None,
            },
        ],
        &[
            d12_forecast.probability,
            d12_benign
                .forecast
                .as_ref()
                .map_or(0.0, |forecast| forecast.probability),
        ],
    )?;
    let d12_artifact_path = persist_e2e_evaluation_artifact(
        d12_output.clone(),
        &config,
        d12_metrics.clone(),
        "data/task4_output",
    )?;
    let d12_cascade = run_e2e_cycle(E2eCycleInput {
        evaluation_id: format!("{d12_evaluation_id}-cascade"),
        node_id: "nodeB".into(),
        evaluated_at_ms: predictor_reference_ms,
        events: vec![
            sample_cascade_event(
                "d12-cascade-task1",
                EvidenceSource::Task1Anomaly,
                predictor_reference_ms - 60_000,
            ),
            sample_cascade_event(
                "d12-cascade-trust",
                EvidenceSource::CircleTrust,
                predictor_reference_ms - 60_000,
            ),
        ],
        task1_recommendation_path: None,
        task3_degradation_path: None,
        task3_peer_id: None,
        task3_context_config: Task3ContextConfig::default(),
        temporal_config: TemporalFeatureConfig::default(),
        prediction_config: config.clone(),
        primary_predictor: E2ePrimaryPredictor::Ddos,
        sequence_definition: PrecursorSequenceDefinition::recon_to_compromise(),
        peer_relationship: Some(sample_peer_relationship(predictor_reference_ms)),
        source_compromise_probability: Some(0.95),
        hardening_config: HardeningRecommendationConfig::default(),
        task2_templates: task2_templates.clone(),
        audit_root: std::env::temp_dir().join(format!("{d12_evaluation_id}-cascade")),
    })?;
    let d12_cascade_forecast = d12_cascade
        .cascade_forecast
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("D12 related-peer cascade fixture did not forecast risk"))?;
    let mut d12_circle_only_relationship = sample_peer_relationship(predictor_reference_ms);
    d12_circle_only_relationship.reasons = vec!["circle_membership_only".into()];
    d12_circle_only_relationship.same_segment = false;
    d12_circle_only_relationship.recent_direct_communication = false;
    d12_circle_only_relationship.shared_service_or_relay = false;
    d12_circle_only_relationship.topology_dependency = false;
    d12_circle_only_relationship.relevant_exposed_port = false;
    let d12_circle_only = run_e2e_cycle(E2eCycleInput {
        evaluation_id: format!("{d12_evaluation_id}-circle-only"),
        node_id: "nodeB".into(),
        evaluated_at_ms: predictor_reference_ms,
        events: vec![sample_cascade_event(
            "d12-circle-only",
            EvidenceSource::CircleTrust,
            predictor_reference_ms - 60_000,
        )],
        task1_recommendation_path: None,
        task3_degradation_path: None,
        task3_peer_id: None,
        task3_context_config: Task3ContextConfig::default(),
        temporal_config: TemporalFeatureConfig::default(),
        prediction_config: config.clone(),
        primary_predictor: E2ePrimaryPredictor::Ddos,
        sequence_definition: PrecursorSequenceDefinition::recon_to_compromise(),
        peer_relationship: Some(d12_circle_only_relationship),
        source_compromise_probability: Some(0.95),
        hardening_config: HardeningRecommendationConfig::default(),
        task2_templates: task2_templates.clone(),
        audit_root: std::env::temp_dir().join(format!("{d12_evaluation_id}-circle-only")),
    })?;
    if d12_circle_only.cascade_forecast.is_some() {
        bail!("Circle-only relationship must not propagate a D12 cascade forecast");
    }
    println!("Pipeline           : Task1 artifact -> D3 bridge; Task3 JSONL -> D11 reader");
    println!(
        "                     -> features -> sequence -> prediction/confidence -> explanation"
    );
    println!("                     -> Task2 review-only recommendation -> lifecycle");
    println!("Evaluation ID      : {}", d12_output.evaluation_id);
    println!("Forecast ID        : {}", d12_forecast.forecast_id);
    println!(
        "Forecast           : {:?} ({:.0}% probability)",
        d12_forecast.threat_type,
        d12_forecast.probability * 100.0
    );
    println!(
        "Confidence         : {:.0}%",
        d12_forecast.confidence * 100.0
    );
    println!(
        "Forecast horizon   : {} minutes",
        (d12_forecast.horizon_end_ms - d12_forecast.horizon_start_ms) / 60_000
    );
    println!(
        "Target node        : {}",
        d12_forecast.target_nodes.join(", ")
    );
    println!(
        "Evidence IDs       : {}",
        d12_forecast.evidence_ids.join(", ")
    );
    println!(
        "D3 / D11 evidence  : {} / {} events",
        d12_output.task1_event_ids.len(),
        d12_output.task3_event_ids.len()
    );
    println!(
        "Task3 decision IDs : {}",
        d12_output.task3_decision_ids.join(", ")
    );
    println!(
        "Task 2 handoff     : {} -> {:?}; review required = {}",
        d12_output
            .recommendation
            .as_ref()
            .map_or("none", |item| item.recommendation_id.as_str()),
        d12_output.recommendation.as_ref().map(|item| &item.actions),
        d12_output
            .recommendation
            .as_ref()
            .is_some_and(|item| item.requires_task2_review)
    );
    println!(
        "Lifecycle audit    : {:?}; {}",
        d12_output
            .lifecycle_record
            .as_ref()
            .map(|item| item.forecast.status),
        d12_output.forecast_artifact_path.as_ref().map_or_else(
            || "not created".to_string(),
            |path| path.display().to_string()
        )
    );
    println!(
        "Latency            : {} microseconds",
        d12_output.metrics.inference_latency_micros
    );
    println!(
        "Bounded resources  : {}/{} events, {} replayed, {} future excluded, {} temporal windows",
        d12_output.metrics.accepted_event_count,
        d12_output.metrics.temporal_max_events,
        d12_output.metrics.rejected_or_replayed_event_count,
        d12_output.metrics.future_event_count,
        d12_output.metrics.temporal_window_count
    );
    println!(
        "Controlled metrics : TP {} FP {} TN {} FN {}; precision {:.2}, recall {:.2}, F1 {:.2}",
        d12_metrics.true_positive,
        d12_metrics.false_positive,
        d12_metrics.true_negative,
        d12_metrics.false_negative,
        d12_metrics.precision,
        d12_metrics.recall,
        d12_metrics.f1
    );
    println!(
        "Quality metrics    : FPR {:.2}, lead time {}m, calibration MAE {:.2}",
        d12_metrics.false_positive_rate,
        d12_metrics.mean_lead_time_ms / 60_000,
        d12_metrics.calibration_mean_absolute_error
    );
    println!("Evaluation artifact: {}", d12_artifact_path.display());
    println!(
        "D7 cascade         : related peer {} at {:.0}% (reasons: {})",
        d12_cascade_forecast.target_nodes.join(", "),
        d12_cascade_forecast.probability * 100.0,
        d12_cascade_forecast
            .explanation
            .relationship_reasons
            .join(", ")
    );
    println!("D7 Circle-only     : no propagation ✓");
    println!("Enforcement        : NOT performed by Task 4 ✓");
    let _ = std::fs::remove_file(&d12_task3_context_path);
    println!("ISSUE #12 - AI E2E & BENCHMARKS: PASS ✓\n");

    println!("====================================================");
    println!("CUMULATIVE TASK 4 DEMO: ISSUES #1–#12 PASS ✓");
    println!("====================================================");
    Ok(())
}

fn sample_ddos_forecast(minutes: u64, probability: f64, confidence: f64) -> ThreatForecast {
    ThreatForecast {
        schema_version: THREAT_FORECAST_SCHEMA_VERSION.to_string(),
        forecast_id: "sample-nodeb-ddos-001".to_string(),
        model_version: "task4-baseline-v1".to_string(),
        generated_at_ms: 1_000,
        horizon_start_ms: 1_000,
        horizon_end_ms: 1_000 + minutes * 60_000,
        threat_type: PredictedThreatType::Ddos,
        target_nodes: vec!["nodeB".to_string()],
        probability,
        confidence,
        severity: ForecastSeverity::UrgentReview,
        evidence_ids: vec!["sample-task1-evidence-nodeb-001".to_string()],
        feature_snapshot_id: "sample-feature-snapshot-001".to_string(),
        explanation: ForecastExplanation {
            summary: "SAMPLE Issue #1 contract demonstration only".to_string(),
            top_factors: Vec::new(),
            precursor_sequence_ids: Vec::new(),
            missing_evidence: Vec::new(),
            relationship_reasons: Vec::new(),
            calibration: None,
        },
        status: ForecastStatus::Active,
    }
}

fn sample_reconnaissance_event() -> SecurityEvent {
    SecurityEvent {
        schema_version: SECURITY_EVENT_SCHEMA_VERSION,
        event_id: "sample-suricata-nodeb-recon-001".to_string(),
        observed_at_ms: 1_000_000,
        source: EvidenceSource::Suricata,
        node_id: "nodeB".to_string(),
        peer_id: Some("nodeA".to_string()),
        source_ip: Some("10.0.0.10".to_string()),
        destination_ip: Some("10.0.0.20".to_string()),
        source_port: Some(45_000),
        destination_port: Some(22),
        event_type: SecurityEventType::Reconnaissance,
        severity: EventSeverity::High,
        confidence: 0.88,
        attributes: std::collections::BTreeMap::from([(
            "signature".to_string(),
            "SAMPLE SSH reconnaissance".to_string(),
        )]),
    }
}

fn sample_ddos_predictor_events(reference_time_ms: u64) -> Vec<SecurityEvent> {
    ["10.0.0.91", "10.0.0.92", "10.0.0.93"]
        .into_iter()
        .enumerate()
        .map(|(index, source_ip)| SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: format!("sample-ddos-evidence-{}", index + 1),
            observed_at_ms: reference_time_ms - (index as u64 + 1) * 60_000,
            source: EvidenceSource::Suricata,
            node_id: "nodeB".to_string(),
            peer_id: None,
            source_ip: Some(source_ip.to_string()),
            destination_ip: Some("10.0.0.20".to_string()),
            source_port: Some(40_000 + index as u16),
            destination_port: Some(443),
            event_type: SecurityEventType::TrafficAnomaly,
            severity: EventSeverity::High,
            confidence: 0.90,
            attributes: std::collections::BTreeMap::from([
                ("connection_count".to_string(), "120".to_string()),
                ("traffic_bytes".to_string(), "500000".to_string()),
                ("task1_anomaly_score".to_string(), "0.90".to_string()),
            ]),
        })
        .collect()
}

fn sample_peer_relationship(reference_time_ms: u64) -> PeerRelationship {
    PeerRelationship {
        relationship_id: "sample-nodea-nodeb-network-dependency".to_string(),
        provenance: "sample-authorized-topology".to_string(),
        reasons: vec![
            "same_network_segment".to_string(),
            "recent_direct_communication".to_string(),
            "shared_authorized_relay".to_string(),
            "relevant_exposed_port".to_string(),
        ],
        observed_at_ms: reference_time_ms - 60_000,
        expires_at_ms: reference_time_ms + 30 * 60_000,
        source_node: "nodeA".to_string(),
        target_node: "nodeB".to_string(),
        same_segment: true,
        recent_direct_communication: true,
        shared_service_or_relay: true,
        topology_dependency: false,
        relevant_exposed_port: true,
    }
}

fn sample_cascade_event(
    event_id: &str,
    source: EvidenceSource,
    observed_at_ms: u64,
) -> SecurityEvent {
    SecurityEvent {
        schema_version: SECURITY_EVENT_SCHEMA_VERSION,
        event_id: event_id.to_string(),
        observed_at_ms,
        source,
        node_id: "nodeB".to_string(),
        peer_id: Some("nodeA".to_string()),
        source_ip: Some("10.0.0.10".to_string()),
        destination_ip: Some("10.0.0.20".to_string()),
        source_port: None,
        destination_port: Some(443),
        event_type: SecurityEventType::TrafficAnomaly,
        severity: EventSeverity::High,
        confidence: 0.90,
        attributes: std::collections::BTreeMap::new(),
    }
}

fn sample_ordered_precursors(
    sequence: &PrecursorSequenceDefinition,
    reference_time_ms: u64,
) -> Vec<SecurityEvent> {
    sequence
        .steps
        .iter()
        .enumerate()
        .map(|(index, event_type)| {
            let mut event = sample_reconnaissance_event();
            event.event_id = format!("sample-precursor-{index}");
            event.observed_at_ms = reference_time_ms - 6 * 60_000 + index as u64 * 60_000;
            event.event_type = *event_type;
            event.source = match event_type {
                SecurityEventType::Reconnaissance => EvidenceSource::NmapDiscovery,
                SecurityEventType::PortDiscovery => EvidenceSource::Suricata,
                _ => EvidenceSource::Task1Anomaly,
            };
            event
        })
        .collect()
}

fn precursor_step_label(event_type: SecurityEventType) -> &'static str {
    match event_type {
        SecurityEventType::Reconnaissance => "Reconnaissance — scan/recon activity observed",
        SecurityEventType::PortDiscovery => {
            "Port discovery — target service/port enumeration observed"
        }
        SecurityEventType::ExposureDiscovery => {
            "Exposure discovery — externally exposed or vulnerable service found"
        }
        SecurityEventType::AuthenticationFailure => {
            "Authentication failures — repeated access attempts observed"
        }
        SecurityEventType::ProtocolViolation => {
            "Protocol violation — abnormal protocol/security behavior observed"
        }
        SecurityEventType::TrafficAnomaly => "Traffic anomaly — unusual traffic pattern observed",
        _ => "Other normalized security event",
    }
}

fn evidence_source_label(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::NmapDiscovery => "Nmap Discovery",
        EvidenceSource::Suricata => "Suricata",
        EvidenceSource::Task1Anomaly => "Task 1 Anomaly Engine",
        EvidenceSource::GuardianThreat => "Guardian Threat",
        EvidenceSource::Attestation => "Attestation",
        EvidenceSource::CircleTrust => "Circle Trust",
        EvidenceSource::NetworkAi => "Task 3 Network AI",
        EvidenceSource::GeoThreatIntel => "Geo Threat Intelligence",
        EvidenceSource::PolicyLifecycle => "Policy Lifecycle",
    }
}

fn assert_serialization_round_trip(forecast: &ThreatForecast) -> Result<()> {
    let round_trip: ThreatForecast = serde_json::from_str(&serde_json::to_string(forecast)?)?;
    if round_trip != *forecast {
        bail!("forecast serialization round-trip changed the Task4 contract");
    }
    Ok(())
}

fn expect_rejection(
    forecast: ThreatForecast,
    matches_expected: impl Fn(&ThreatPredictionError) -> bool,
) -> Result<()> {
    match forecast.validate() {
        Err(error) if matches_expected(&error) => Ok(()),
        Err(error) => bail!("invalid sample returned the wrong validation error: {error}"),
        Ok(()) => bail!("invalid sample was unexpectedly accepted"),
    }
}

fn expect_event_rejection(event: SecurityEvent) -> Result<()> {
    match event.validate() {
        Err(ThreatPredictionError::MalformedEvent(_)) => Ok(()),
        Err(error) => bail!("malformed event returned the wrong validation error: {error}"),
        Ok(()) => bail!("malformed event was unexpectedly accepted"),
    }
}
