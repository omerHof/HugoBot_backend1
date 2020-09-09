
class Tables(Resource):
    @app.route('/', methods=("POST", "GET"))
    def get(self, identifier):
        dataObject = oneTimeInit('only')

        if identifier == 'getFullTable':
            df = pd.DataFrame(dataObject.__getattr__("fullTable"))
            # table_columns = ["KL Params", "Study Design", "Observation Period", "Overlap",
            #                  "Discretization Method", "Bins", "TIRPs Representation", "Classifier", "AUC", "Recall",
            #                  "Precision", "Accuracy", "Runtime"]

            fig = go.Figure(data=[go.Table(
                header=dict(values=[
                    'Discretization Method', 'Bins', 'TIRPs Representation', 'Classifier',
                    'AUC', 'Recall', 'Precision', 'Accuracy', 'Runtime'],
                    fill_color='paleturquoise',
                    align='left'),
                cells=dict(values=[
                    df['Discretization Method'], df['Bins'], df['TIRPs Representation'],
                    df['Classifier'], df['AUC'], df['Recall'], df['Precision'], df['Accuracy'],
                    df['Runtime']],
                    fill_color='lavender',
                    align='left'))
            ])
            fig.update_layout(width=2000, height=1000)
            return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)