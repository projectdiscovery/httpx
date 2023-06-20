package errorpageclassifier

import "fmt"

type ConfusionMatrix struct {
	matrix [][]int
	labels []string
}

func NewConfusionMatrix(actual, predicted []string, labels []string) *ConfusionMatrix {
	n := len(labels)
	matrix := make([][]int, n)
	for i := range matrix {
		matrix[i] = make([]int, n)
	}

	labelIndices := make(map[string]int)
	for i, label := range labels {
		labelIndices[label] = i
	}

	for i := range actual {
		matrix[labelIndices[actual[i]]][labelIndices[predicted[i]]]++
	}

	return &ConfusionMatrix{
		matrix: matrix,
		labels: labels,
	}
}

func (cm *ConfusionMatrix) PrintConfusionMatrix() {
	fmt.Printf("%30s\n", "Confusion Matrix")
	fmt.Println()
	// Print header
	fmt.Printf("%-15s", "")
	for _, label := range cm.labels {
		fmt.Printf("%-15s", label)
	}
	fmt.Println()

	// Print rows
	for i, row := range cm.matrix {
		fmt.Printf("%-15s", cm.labels[i])
		for _, value := range row {
			fmt.Printf("%-15d", value)
		}
		fmt.Println()
	}
	fmt.Println()
}

func (cm *ConfusionMatrix) PrintClassificationReport() {
	fmt.Printf("%30s\n", "Classification Report")
	fmt.Println()

	fmt.Printf("\n%-15s %-10s %-10s %-10s %-10s\n", "", "precision", "recall", "f1-score", "support")

	totals := map[string]float64{"true": 0, "predicted": 0, "correct": 0}
	macroAvg := map[string]float64{"precision": 0, "recall": 0, "f1-score": 0}

	for i, label := range cm.labels {
		truePos := cm.matrix[i][i]
		falsePos, falseNeg := 0, 0
		for j := 0; j < len(cm.labels); j++ {
			if i != j {
				falsePos += cm.matrix[j][i]
				falseNeg += cm.matrix[i][j]
			}
		}

		precision := float64(truePos) / float64(truePos+falsePos)
		recall := float64(truePos) / float64(truePos+falseNeg)
		f1Score := 2 * precision * recall / (precision + recall)
		support := truePos + falseNeg

		fmt.Printf("%-15s %-10.2f %-10.2f %-10.2f %-10d\n", label, precision, recall, f1Score, support)

		totals["true"] += float64(support)
		totals["predicted"] += float64(truePos + falsePos)
		totals["correct"] += float64(truePos)

		macroAvg["precision"] += precision
		macroAvg["recall"] += recall
		macroAvg["f1-score"] += f1Score
	}

	accuracy := totals["correct"] / totals["true"]
	fmt.Printf("\n%-26s %-10s %-10.2f %-10d", "accuracy", "", accuracy, int(totals["true"]))

	fmt.Printf("\n%-15s %-10.2f %-10.2f %-10.2f %-10d\n", "macro avg",
		macroAvg["precision"]/float64(len(cm.labels)),
		macroAvg["recall"]/float64(len(cm.labels)),
		macroAvg["f1-score"]/float64(len(cm.labels)),
		int(totals["true"]))

	precisionWeightedAvg := totals["correct"] / totals["predicted"]
	recallWeightedAvg := totals["correct"] / totals["true"]
	f1ScoreWeightedAvg := 2 * precisionWeightedAvg * recallWeightedAvg / (precisionWeightedAvg + recallWeightedAvg)

	fmt.Printf("%-15s %-10.2f %-10.2f %-10.2f %-10d\n", "weighted avg",
		precisionWeightedAvg, recallWeightedAvg, f1ScoreWeightedAvg, int(totals["true"]))

	fmt.Println()
}
