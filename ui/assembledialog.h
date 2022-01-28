#pragma once

#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include "binaryninjaapi.h"
#include "dialogtextedit.h"
#include "uicontext.h"

class BINARYNINJAUIAPI AssembleDialog : public QDialog
{
	Q_OBJECT

	BinaryViewRef m_view;
	uint64_t m_addr;
	size_t m_length;
	QComboBox* m_archSelection;
	ArchitectureRef m_fixedArch;
	DialogTextEdit* m_code;
	BinaryNinja::DataBuffer m_bytes;
	bool m_setDefault;

  public:
	AssembleDialog(QWidget* parent, BinaryViewRef data, uint64_t addr, ArchitectureRef prefArch = NULL,
	    const QString& code = "", bool fixedArch = false);

	ArchitectureRef getArchitecture();
	const BinaryNinja::DataBuffer& getBytes() const { return m_bytes; }
	void setLength(size_t len) { m_length = len; }

  private Q_SLOTS:
	void saveOnFinish(int result);
	void assemble();

  protected:
	virtual void accept() override;
};
