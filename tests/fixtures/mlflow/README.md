# MLflow test fixture

A real MLflow 3.16.1 file-store tree (`mlruns/`), created with
`MLFLOW_ALLOW_FILE_STORE=true` by logging one run (`tiny-addn`) with two
params (`n`, `learning_rate`), an `accuracy` metric over three steps, a
`mlflow.source.git.commit` tag and a `mlflow.pyfunc` model with
`pip_requirements=["numpy==1.26.4"]`.

In MLflow 3 the logged model lives beside the run, in
`mlruns/<experiment>/models/<model_id>/artifacts`, and names its run in
`meta.yaml` (`source_run_id`).

`python_model.pkl` is a cloudpickle file, as MLflow writes for every pyfunc
model. The tests only scan it statically; it is never loaded. The pickle scan
reports it as `dangerous` (cloudpickle rebuilds functions and classes from
code), which is the point: loading an MLflow pyfunc model runs code.
