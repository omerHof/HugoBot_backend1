
class Graphs(Resource):

    def get(self, identifier):
        dataObject = oneTimeInit('only')
        table = pd.DataFrame(dataObject.__getattr__("fullTable"))

        # parse req
        parser = reqparse.RequestParser()
        parser.add_argument('classifierName', required=False)
        parser.add_argument('Classifiers', required=False)

        # Parse the arguments into an object
        args = parser.parse_args()

        # classifierName = "Decision Tree"

        if identifier == 'getAllClassifiersGraphs':
            responseDict = {}

            auc_section = {
                'per_Classifier': json.dumps(vis.Classifier_With_ConfidenceInterval(table, 'AUC'),
                                             cls=plotly.utils.PlotlyJSONEncoder),
                'Bin_VS_Abstraction': json.dumps(vis.get_Bin_VS_Abstraction_AllClassifiersAVG(table, 'AUC'),
                                                 cls=plotly.utils.PlotlyJSONEncoder),
                'Bin_VS_TIRPsRepresentation': json.dumps(vis.get_Bin_VS_DataRepresentation_AllClassifiersAVG(
                    table, 'AUC'), cls=plotly.utils.PlotlyJSONEncoder),
                'Classifier_VS_TIRPsRepresentation': json.dumps(
                    vis.get_Classifier_VS_DataRepresentation(table, 'AUC'), cls=plotly.utils.PlotlyJSONEncoder)}

            responseDict['Evaluated by AUC'] = auc_section

            runtime_section = {
                'per_Classifier': json.dumps(vis.Classifier_With_ConfidenceInterval(
                    table, 'Runtime'), cls=plotly.utils.PlotlyJSONEncoder),
                'Bin_VS_Abstraction': json.dumps(vis.get_Bin_VS_Abstraction_AllClassifiersAVG(table, 'Runtime'),
                                                 cls=plotly.utils.PlotlyJSONEncoder),
                'Bin_VS_TIRPsRepresentation': json.dumps(
                    vis.get_Bin_VS_DataRepresentation_AllClassifiersAVG(table, 'Runtime'),
                    cls=plotly.utils.PlotlyJSONEncoder),
                'Classifier_VS_DataRepresentation': json.dumps(
                    vis.get_Classifier_VS_DataRepresentation(table, 'Runtime'), cls=plotly.utils.PlotlyJSONEncoder)}
            responseDict['Evaluated by Runtime'] = runtime_section

            return json.dumps(responseDict)



        elif identifier == 'getTopThreeGraphs':
            top_three = vis.get_top_three_df(table)
            responseDict = {
                'Configuration_VS_Score': json.dumps(vis.generateGeneralGraphTopThreeEvaluatedByAUC(top_three),
                                                     cls=plotly.utils.PlotlyJSONEncoder),
                'Bins_VS_Discretization': json.dumps(
                    vis.generateGraphTopThreeEvaluatedByAUC(top_three, 'Bins', 'Discretization Method'),
                    cls=plotly.utils.PlotlyJSONEncoder),
                'Bins_VS_TIRPS': json.dumps(
                    vis.generateGraphTopThreeEvaluatedByAUC(top_three, 'Bins', 'TIRPs Representation'),
                    cls=plotly.utils.PlotlyJSONEncoder),
                'Classifiers_VS_TIRPS': json.dumps(
                    vis.generateGraphTopThreeEvaluatedByAUC(top_three, 'Classifier', 'TIRPs Representation'),
                    cls=plotly.utils.PlotlyJSONEncoder),
                'ClassifiersGeneral': json.dumps(
                    vis.generateGeneralGraphTopThreeEvaluatedByAUC(top_three),
                    cls=plotly.utils.PlotlyJSONEncoder)
                }
            return json.dumps(responseDict)

        elif identifier == 'getSpecificClassifierGraphs':
            classifierNames = json.loads(request.headers['Classifiers'])
            responseDict = {}
            allDf = vis.getDfPerClassifier(table)

            for classifier in classifierNames:
                specificDf = vis.getSpecificClassifierDf(allDf, classifier)
                responseDict['AUC_Bins_VS_Discretization_' + classifier] = json.dumps(
                    vis.generateLineGraphEvaluatedBy(specificDf, 'Bins', 'Discretization Method', 'single', True,
                                                     'AUC'), cls=plotly.utils.PlotlyJSONEncoder)
                responseDict['AUC_Bins_VS_TIRPS_' + classifier] = json.dumps(
                    vis.generateLineGraphEvaluatedBy(specificDf, 'Bins', 'TIRPs Representation', 'single', True, 'AUC'),
                    cls=plotly.utils.PlotlyJSONEncoder)
                responseDict['RUNTIME_Bins_VS_Discretization_' + classifier] = json.dumps(
                    vis.generateLineGraphEvaluatedBy(specificDf, 'Bins', 'Discretization Method', 'single', True,
                                                     'Runtime'), cls=plotly.utils.PlotlyJSONEncoder)
                responseDict['RUNTIME_Bins_VS_TIRPs_' + classifier] = json.dumps(
                    vis.generateLineGraphEvaluatedBy(specificDf, 'Bins', 'TIRPs Representation', 'single', True,
                                                     'Runtime'), cls=plotly.utils.PlotlyJSONEncoder)

            return json.dumps(responseDict)

        elif identifier == 'getClassifersOptions':
            return json.dumps(table.Classifier.unique().tolist())

        elif identifier == 'getTopThreeConfigurations':
                return returnFolderAllImagesJson('TopThreeOtherGraphs','jpeg')
        else:  # not good
            return {'message': 'Bad Call identifier', 'data': {}}, 404

        #
        # if df.empty:
        #     return {'message': 'request not found', 'data': {}}, 404

        # df.dropna(how='all')
        # table = df.to_json()
        # print(table)
        table = ""
        return {'message': 'Success', 'data': table}, 200

