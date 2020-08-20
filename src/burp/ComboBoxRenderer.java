package burp;

import javax.swing.*;
import java.awt.*;

class ComboBoxRenderer extends JLabel implements ListCellRenderer<Object> {
    public Component getListCellRendererComponent(JList<? extends Object> list,
                                                  Object value, int index, boolean isSelected, boolean cellHasFocus) {
        if(value instanceof JSeparator){
            return (Component)value;
        }else{
            setText(value.toString());
        }
        return this;
    }
}