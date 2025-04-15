package org.burp;

import burp.*;
import com.alibaba.fastjson.JSONPath;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONException;
import com.alibaba.fastjson2.JSONObject;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.*;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();//记录原始流量
    private final List<LogEntry> log2 = new ArrayList<LogEntry>();//记录攻击流量
    private final List<LogEntry> log3 = new ArrayList<LogEntry>();//用于展现
    private final List<Request_md5> log4_md5 = new ArrayList<Request_md5>();//用于存放数据包的md5
    private IHttpRequestResponse currentlyDisplayedItem;
    public PrintWriter stdout;
    int switchs = 1; //开关 0关 1开
    int clicks_Repeater=0;//64是监听 0是关闭
    int clicks_Proxy=0;//4是监听 0是关闭
    int conut = 0; //记录条数
    String data_md5_id; //用于判断目前选中的数据包
    public AbstractTableModel model = new MyModel();
    //int original_data_len;//记录原始数据包的长度
    int is_int = 1; //开关 0关 1开;//纯数据是否进行-1，-0
    String temp_data; //用于保存临时内容
    int JTextArea_int = 0;//自定义payload开关  0关 1开
    String JTextArea_data_1 = "";//文本域的内容
    int diy_payload_1 = 1;//自定义payload空格编码开关  0关 1开
    int diy_payload_2 = 0;//自定义payload值置空开关  0关 1开
    int select_row = 0;//选中表格的行数
    Table logTable; //第一个表格框
    int is_cookie = -1;//cookie是否要注入，-1关闭 2开启。
    String white_URL = "";
    int white_switchs = 0;//白名单开关
    String customParamsTextAreaData = "";//文本域的内容
    int JTextAreaCustomParams= 0;//自定义参数开关  0关 1开
    int customParamsAddpayload= 0;//自定义参数开关  0关 1开
    int Payloadlayers = 0;


    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        //输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello xia sql!");
        this.stdout.println("你好 欢迎使用 瞎注!");
        this.stdout.println("version:4.1");
        this.stdout.println("感谢名单：Moonlit、阿猫阿狗、Shincehor");



        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("xia SQL V4.1");

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {

                // main split pane
                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // table of log entries
                logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable); //给列表添加滚动条



                //test

                JPanel jp=new JPanel(new BorderLayout());
                JLabel jl=new JLabel("==>");//创建一个标签
                jl.setMaximumSize(new Dimension(5,100));

                Table_log2 table=new Table_log2(model);
                JScrollPane pane=new JScrollPane(table);//给列表添加滚动条
                JSplitPane splitlogPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                splitlogPane.setLeftComponent(scrollPane);
                JSplitPane splitresultPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                splitresultPane.setLeftComponent(jl);
                splitresultPane.setRightComponent(pane);
                splitresultPane.setDividerLocation(30); // Set divider to a fixed position
                splitresultPane.setEnabled(false); // Disable resizing
                splitlogPane.setRightComponent(splitresultPane);

                jp.add(splitlogPane);
                //侧边复选框
                JPanel jps=new JPanel();
                jps.setLayout(new GridLayout(16, 1)); //六行一列
                JLabel jls=new JLabel("插件名：瞎注 author：算命縖子");    //创建一个标签
               // JLabel jls_1=new JLabel("blog:www.nmd5.com");    //创建一个标签
                JLabel jls_2=new JLabel("版本：xia SQL V4.1");    //创建一个标签
                JLabel jls_3=new JLabel("感谢名单：Moonlit、阿猫阿狗、Shincehor");    //创建一个标签
                JCheckBox chkbox1=new JCheckBox("启动插件", true);    //创建指定文本和状态的复选框
                JCheckBox chkbox2=new JCheckBox("监控Repeater");    //创建指定文本的复选框
                JCheckBox chkbox3=new JCheckBox("监控Proxy");    //创建指定文本的复选框
                JCheckBox chkbox4=new JCheckBox("值是数字则进行-1、-0",true);    //创建指定文本的复选框
                JLabel jls_4=new JLabel("修改payload后记得点击加载");    //创建一个标签
                JCheckBox chkbox5=new JCheckBox("自定义payload");    //创建指定文本的复选框
                JCheckBox chkbox6=new JCheckBox("自定义payload中空格url编码",true);    //创建指定文本的复选框
                JCheckBox chkbox7=new JCheckBox("自定义payload中参数值置空");    //创建指定文本的复选框
                JCheckBox chkbox8=new JCheckBox("测试Cookie");    //创建指定文本的复选框
                JCheckBox customParamsCheckbox =new JCheckBox("开启额外参数");
                JCheckBox customParamsAddPayloadCheckbox =new JCheckBox("额外参数应用payload");
                JButton customParamsPersistBtn=new JButton("持久化额外参数");    //创建JButton对象
                JLabel jls_5=new JLabel("如果需要多个域名加白请用,隔开");    //创建一个标签
                JTextField textField = new JTextField("填写白名单域名");//白名单文本框
                // 创建下拉框（JComboBox）选项
                String[] options = {"不限", "1", "2", "3", "4","5","6"};
                JComboBox<String> comboBox = new JComboBox<>(options);
                comboBox.setSelectedIndex(0);
                JLabel jComboBoxlabel=new JLabel("JSON参数payload最大深度:");
                JPanel jComboBoxPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                // 设置默认选择项为“全部”
                jComboBoxPanel.add(jComboBoxlabel);
                jComboBoxPanel.add(comboBox);


                JButton btn1=new JButton("清空列表");    //创建JButton对象
                JButton btn2=new JButton("加载/重新加载payload");    //创建JButton对象
                JButton btn3=new JButton("启动白名单");    //处理白名单


                //自定义payload区
                JPanel jps_2=new JPanel();

                jps_2.setLayout(new BorderLayout());
                jps_2.setMinimumSize(new Dimension(100,200));
                JTextArea jta=new JTextArea("[\"'\",\"''\"] \n[\"-0\"，\"-1\"];;;[0-9]+",10,16);
                JTextArea jta2=new JTextArea("",10,16);

                //读取ini配置文件
                try {
                    BufferedReader in = new BufferedReader(new FileReader("xia_SQL_diy_payload.ini"));
                    String str,str_data="";
                    while ((str = in.readLine()) != null) {
                        str_data += str+"\n";
                    }
                    jta.setText(str_data);

                    BufferedReader in2 = new BufferedReader(new FileReader("xia_SQL_diy_customParam.ini"));
                    String str2,str_data2="";
                    while ((str2 = in2.readLine()) != null) {
                        str_data2 += str2+"\n";
                    }
                    jta2.setText(str_data2);

                } catch (IOException e) {
                }

                //jta.setLineWrap(true);    //设置文本域中的文本为自动换行
                jta.setForeground(Color.BLACK);    //设置组件的背景色
                jta.setFont(new Font("楷体",Font.BOLD,16));    //修改字体样式
                jta.setBackground(Color.LIGHT_GRAY);    //设置背景色
                jta.setEditable(false);//不可编辑状态
                JScrollPane jsp=new JScrollPane(jta);    //将文本域放入滚动窗口
                jps_2.add(jsp,BorderLayout.CENTER);

                //自定义参数区
                JPanel customParamsLabPanel=new JPanel();
                customParamsLabPanel.setLayout(new BorderLayout());
                JPanel customParamsCheck = new JPanel(new FlowLayout(FlowLayout.LEFT));
                customParamsCheckbox.setMaximumSize(new Dimension(100,100));
                customParamsAddPayloadCheckbox.setMaximumSize(new Dimension(100,100));
                customParamsCheck.add(customParamsCheckbox);
                //customParamsCheck.add(customParamsAddPayloadCheckbox);
                customParamsCheck.add(customParamsPersistBtn);
                customParamsLabPanel.add(customParamsCheck, BorderLayout.NORTH);

                jta2.setForeground(Color.BLACK);    //设置组件的背景色
                jta2.setFont(new Font("楷体",Font.BOLD,16));    //修改字体样式
                jta2.setBackground(Color.LIGHT_GRAY);    //设置背景色
                jta2.setEditable(false);//不可编辑状态
                JScrollPane jsp2=new JScrollPane(jta2);
                customParamsLabPanel.add(jsp2, BorderLayout.CENTER);

                //添加复选框监听事件
                chkbox1.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox1.isSelected()){
                            stdout.println("插件xia SQl启动");
                            switchs = 1;
                        }else {
                            stdout.println("插件xia SQL关闭");
                            switchs = 0;
                        }

                    }
                });
                chkbox2.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (chkbox2.isSelected()){
                            stdout.println("启动 监控Repeater");
                            clicks_Repeater = 64;
                        }else {
                            stdout.println("关闭 监控Repeater");
                            clicks_Repeater = 0;
                        }
                    }
                });
                chkbox3.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox3.isSelected()) {
                            stdout.println("启动 监控Proxy");
                            clicks_Proxy = 4;
                        }else {
                            stdout.println("关闭 监控Proxy");
                            clicks_Proxy = 0;
                        }
                    }
                });
                chkbox4.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox4.isSelected()) {
                            stdout.println("启动 值是数字则进行-1、-0");
                            is_int = 1;
                        }else {
                            stdout.println("关闭 值是数字则进行-1、-0");
                            is_int = 0;
                        }
                    }
                });

                chkbox5.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox5.isSelected()) {
                            stdout.println("启动 自定义payload");
                            jta.setEditable(true);
                            jta.setBackground(Color.WHITE);    //设置背景色
                            JTextArea_int = 1;

                            if (diy_payload_1 == 1){
                                String temp_data = jta.getText();
                                temp_data = temp_data.replaceAll(" ","%20");
                                JTextArea_data_1 = temp_data;
                            }else {
                                JTextArea_data_1 = jta.getText();
                            }

                        }else {
                            stdout.println("关闭 自定义payload");
                            jta.setEditable(false);
                            jta.setBackground(Color.LIGHT_GRAY);    //设置背景色
                            JTextArea_int = 0;
                        }
                    }
                });
                // 添加监听器
                comboBox.addActionListener(e -> {
                    String selected = (String) comboBox.getSelectedItem();
                    if ("不限".equals(selected)) {
                        Payloadlayers = 0;
                    } else {
                        Payloadlayers = Integer.parseInt(selected);
                    }
                });
                customParamsCheckbox.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(customParamsCheckbox.isSelected()) {
                            stdout.println("启动 自定义参数");
                            jta2.setEditable(true);
                            jta2.setBackground(Color.WHITE);    //设置背景色
                            JTextAreaCustomParams = 1;
                            customParamsTextAreaData = jta2.getText();
                        }else {
                            stdout.println("关闭 自定义参数");
                            jta2.setEditable(false);
                            jta2.setBackground(Color.LIGHT_GRAY);    //设置背景色
                            JTextAreaCustomParams = 0;
                        }
                    }
                });

                customParamsAddPayloadCheckbox.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(customParamsAddPayloadCheckbox.isSelected()) {
                            stdout.println("启动 自定义参数应用payload");
                            customParamsAddpayload = 1;
                        }else {
                            stdout.println("关闭 自定义参数应用payload");
                            customParamsAddpayload = 0;
                        }
                    }
                });

                chkbox6.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox6.isSelected()) {
                            stdout.println("启动 空格url编码");
                            diy_payload_1 = 1;

                            //空格url编码
                            String temp_data = jta.getText();
                            temp_data = temp_data.replaceAll(" ","%20");
                            JTextArea_data_1 = temp_data;
                        }else {
                            stdout.println("关闭 空格url编码");
                            diy_payload_1 = 0;

                            JTextArea_data_1 = jta.getText();
                        }
                    }
                });

                chkbox7.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox7.isSelected()) {
                            stdout.println("启动 自定义payload参数值置空");
                            diy_payload_2 = 1;
                        }else {
                            stdout.println("关闭 自定义payload参数值置空");
                            diy_payload_2 = 0;
                        }
                    }
                });

                chkbox8.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox8.isSelected()) {
                            stdout.println("启动 测试Cookie");
                            is_cookie = 2;
                        }else {
                            stdout.println("关闭 测试Cookie");
                            is_cookie = -1;
                        }
                    }
                });

                btn1.addActionListener(new ActionListener() {//清空列表
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log.clear();//清除log的内容
                        log2.clear();//清除log2的内容
                        log3.clear();//清除log3的内容
                        log4_md5.clear();//清除log4的内容
                        conut = 0;
                        fireTableRowsInserted(log.size(), log.size());//刷新列表中的展示
                        model.fireTableRowsInserted(log3.size(), log3.size());//刷新列表中的展示
                    }
                });

                btn2.addActionListener(new ActionListener() {//加载自定义payload
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (diy_payload_1 == 1){
                            String temp_data = jta.getText();
                            temp_data = temp_data.replaceAll(" ","%20");
                            JTextArea_data_1 = temp_data;
                        }else {
                            JTextArea_data_1 = jta.getText();
                        }
                        //写入ini配置文件
                        try {
                            BufferedWriter out = new BufferedWriter(new FileWriter("xia_SQL_diy_payload.ini"));
                            out.write(JTextArea_data_1);
                            out.close();
                        } catch (IOException exception) {
                        }
                    }
                });

                customParamsPersistBtn.addActionListener(new ActionListener() {//加载自定义payload
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        //写入ini配置文件
                        try {

                            BufferedWriter out2 = new BufferedWriter(new FileWriter("xia_SQL_diy_customParam.ini"));
                            out2.write(customParamsTextAreaData);
                            out2.close();
                        } catch (IOException exception) {
                        }
                    }
                });


                btn3.addActionListener(new ActionListener() {//加载自定义payload
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if(btn3.getText().equals("启动白名单")){
                            btn3.setText("关闭白名单");
                            white_URL = textField.getText();
                            white_switchs = 1;
                            textField.setEditable(false);
                            textField.setForeground(Color.GRAY);//设置组件的背景色
                        }else {
                            btn3.setText("启动白名单");
                            white_switchs = 0;
                            textField.setEditable(true);
                            textField.setForeground(Color.BLACK);
                        }
                    }
                });

                jta2.getDocument().addDocumentListener(new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent e) {
                        updateCustomParamsTextAreaData();
                    }

                    @Override
                    public void removeUpdate(DocumentEvent e) {
                        updateCustomParamsTextAreaData();
                    }

                    @Override
                    public void changedUpdate(DocumentEvent e) {
                        updateCustomParamsTextAreaData();
                    }

                    private void updateCustomParamsTextAreaData() {
                        customParamsTextAreaData = jta2.getText();
                    }
                });
                jps.add(jls);
                //jps.add(jls_1);
                jps.add(jls_2);
               // jps.add(jls_3);
                jps.add(chkbox1);
                jps.add(chkbox2);
                jps.add(chkbox3);
                //jps.add(chkbox4);
                jps.add(chkbox8);
                jps.add(btn1);
                jps.add(jls_5);
                jps.add(textField);
                jps.add(btn3);
                jps.add(jls_4);
                jps.add(chkbox5);
                jps.add(chkbox6);
                jps.add(chkbox7);
                jps.add(jComboBoxPanel);

               // jps.add(customParamsCheckbox);
                jps.add(btn2);

                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());

                //jp.add(tabs);

                //右边
                splitPanes_2.setLeftComponent(jps);//上面
                JSplitPane splitPanes_4 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPanes_4.setLeftComponent(jps_2);
                splitPanes_4.setRightComponent(customParamsLabPanel);
               // splitPanes_2.setRightComponent(jps_2);//下面
                splitPanes_2.setRightComponent(splitPanes_4);
                //左边
                splitPanes.setLeftComponent(jp);//上面
                splitPanes.setRightComponent(tabs);//下面

                //整体分布
                splitPane.setLeftComponent(splitPanes);//添加在左面
                splitPane.setRightComponent(splitPanes_2);//添加在右面
                splitPane.setDividerLocation(1500);//设置分割的大小

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(pane);
                callbacks.customizeUiComponent(jps);
                callbacks.customizeUiComponent(jp);
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScannerCheck(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);

            }
        });
    }
    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "xia SQL";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //
    // implement IHttpListener
    //




    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

        if(switchs == 1){//插件开关
            if(toolFlag == clicks_Repeater || toolFlag == clicks_Proxy){//监听Repeater
                // only process responses
                if (!messageIsRequest)
                {
                    // create a new log entry with the message details
                    synchronized(log)
                    {
                        //BurpExtender.this.checkVul(messageInfo,toolFlag);
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(messageInfo,toolFlag);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }
                }
            }

        }

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        //右键发送按钮功能

        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        if(invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER || invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_PROXY){
            //父级菜单
            IHttpRequestResponse[] responses = invocation.getSelectedMessages();
            JMenuItem jMenu = new JMenuItem("Send to xia SQL");

            jMenu.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if(switchs == 1) {
                        //不应在Swing事件调度线程中发出HTTP请求，所以需要创建一个Runnable并在 run() 方法中完成工作，后调用 new Thread(runnable).start() 来启动线程
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    BurpExtender.this.checkVul(responses[0], 1024);
                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }else {
                        BurpExtender.this.stdout.println("插件xia SQL关闭状态！");
                    }

                }
            });

            listMenuItems.add(jMenu);


                                       }
            //BurpExtender.this.checkVul(responses,4);
        return listMenuItems;
    }

    private void checkVul(IHttpRequestResponse baseRequestResponse, int toolFlag){
            int original_data_len = 0;
            int is_add=0; //用于判断是否要添加扫描
            String change_sign_1 = ""; //用于显示第一个列表框的状态 变化 部分的内容

            //把当前url和参数进行md5加密，用于判断该url是否已经扫描过
            List<IParameter> paraLists= helpers.analyzeRequest(baseRequestResponse).getParameters();
            IRequestInfo analyzeRequest = helpers.analyzeRequest(baseRequestResponse);
            temp_data = String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl());//url
            byte contentType  = helpers.analyzeRequest(baseRequestResponse).getContentType();
            String[] temp_data_strarray=temp_data.split("\\?");
            String temp_data =(String) temp_data_strarray[0];//获取问号前面的字符串

            //检测白名单
            String[] white_URL_list = white_URL.split(",");
            int white_swith = 0;
            if(white_switchs == 1){
                white_swith = 0;
                for(int i=0;i<white_URL_list.length;i++){
                    if(temp_data.contains(white_URL_list[i])){
                        this.stdout.println("白名单URL！"+temp_data);
                        white_swith = 1;
                    }
                }
                if(white_swith == 0) {
                    this.stdout.println("不是白名单URL！"+temp_data);
                    return;
                }
            }

            //用于判断页面后缀是否为静态文件
            if(toolFlag == 4 || toolFlag ==64){//流量是Repeater与proxy来的就对其后缀判断
                String[] static_file = {"jpg","png","gif","css","js","pdf","mp3","mp4","avi","webp","woff","woff2","doc","docx","csv","xls","xlsx","map","svg"};
                if(temp_data != null && temp_data.contains(".")) {
                    String[] static_file_1 = temp_data.split("\\.");
                    String static_file_2 = static_file_1[static_file_1.length-1].toLowerCase();
                    for(String i : static_file) {
                        if(static_file_2.equals(i)) {
                            this.stdout.println("当前url为静态文件："+temp_data+"\n");
                            return;
                        }
                    }
                }
            }


            String request_data = null;
            is_add = 0;
            for (IParameter para : paraLists){// 循环获取参数，判断类型，再构造新的参数，合并到新的请求包中。
                if (para.getType() == 0 || para.getType() == 1 || para.getType() == 6 || para.getType() == is_cookie) { //getTpe()就是来判断参数是在那个位置的
                    if(is_add == 0){
                        is_add = 1;
                    }
                    temp_data += "+"+para.getName();
                }
            }



            //url+参数进行编码
            temp_data += "+"+helpers.analyzeRequest(baseRequestResponse).getMethod();
            this.stdout.println("\nMD5(\""+temp_data+"\")");
            temp_data = MD5(temp_data);
            this.stdout.println(temp_data);

            for (Request_md5 i : log4_md5){
                if(i.md5_data.equals(temp_data)){//判断md5值是否一样，且右键发送过来的请求不进行md5验证
                    if(toolFlag == 1024){
                        temp_data = String.valueOf(System.currentTimeMillis());
                        this.stdout.println(temp_data);
                        temp_data = MD5(temp_data);
                        this.stdout.println(temp_data);
                    }else {
                        return;
                    }
                }
            }

            //用于判断是否要处理这个请求
            if (is_add != 0){
                log4_md5.add(new Request_md5(temp_data));//保存对应对md5
                stdout.println(is_add);
                stdout.println(request_data);

                int row = log.size();
                try{
                    original_data_len = callbacks.saveBuffersToTempFiles(baseRequestResponse).getResponse().length;//获取原始数据包的长度
                    stdout.println(original_data_len);
                    if(original_data_len <= 0){
                        stdout.println("该数据包无响应");
                        return;
                    }
                } catch (Exception ex) {
                    stdout.println("该数据包无响应");
                    return;
                }

                log.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(baseRequestResponse),helpers.analyzeRequest(baseRequestResponse).getUrl(),"","","",temp_data,0,"run……",999));
                conut += 1;
                fireTableRowsInserted(row, row);
            }
            //获取全部参数
            List<IParameter>paraList= helpers.analyzeRequest(baseRequestResponse).getParameters();
            //判断是否是json
            if(IRequestInfo.CONTENT_TYPE_JSON==contentType){
                try{
                    //如果是CONTENT_TYPE_JSON，先获取原始json参数
                    /*****************获取body **********************/
                    byte[] initRequest = baseRequestResponse.getRequest();
                    int bodyOffset = analyzeRequest.getBodyOffset();
                    String request = new String(initRequest); //byte[] to String
                    String bodyJSONStr = request.substring(bodyOffset);
                    JSONObject bodyJson=JSONObject.parseObject(bodyJSONStr);
                    //获取所有key的路径
                    List<String> bodyPaths=new ArrayList<>();
                    CommonUtil.extractPaths(bodyJson,"",bodyPaths);
                    for(String path : bodyPaths){

                        //超过设置的payload层数，不操作
                        if(Payloadlayers>0){
                            String[] keys=path.split("\\.");
                            if(keys.length>Payloadlayers+1) continue;
                        }
                        //获取该path的值
                        Object vauleOfPath= JSONPath.read(bodyJSONStr,"$"+path);
                        change_sign_1 = execPlayLoad(baseRequestResponse,path,String.valueOf(vauleOfPath),toolFlag,temp_data,IParameter.PARAM_JSON,bodyJSONStr);
                    }
                }catch (Exception e) {
                    return;
                }
            }else {
                // 循环获取参数
                for (IParameter para : paraList){// 循环获取参数
                    //int switch_para = 0;//用来判断该参数是否要处理 0 要处理 1 跳过
                    if (para.getType() == IParameter.PARAM_URL  || para.getType() == IParameter.PARAM_BODY|| para.getType() == is_cookie){ //getTpe()就是来判断参数是在那个位置的
                        String key = para.getName();//获取参数的名称
                        String value = para.getValue();//获取参数的值
                        stdout.println("\n\n原始数据："+key+":"+value);//输出原始的键值数据

                        change_sign_1 = execPlayLoad(baseRequestResponse,key,value,toolFlag,temp_data,para.getType(),null);
                    }

                }
            }
            //必须是get请求，且is_add！=0，页面勾选了 启动额外参数按钮,参数框必须填写了，才执行该逻辑
            if(is_add != 0&&JTextAreaCustomParams==1&&StringUtils.isNotBlank(customParamsTextAreaData)){
                //添加自定义参数
                String[] curstomParams= customParamsTextAreaData.split("\n");;
                for(String curstomParam:curstomParams){
                    byte[] initRequest = baseRequestResponse.getRequest();
                    byte[] newRequest=null;
                    int time_1 = 0,time_2 = 0;
                    //stdout.println(key+":"+value+payload);//输出添加payload的键和值
                    IHttpService iHttpService = baseRequestResponse.getHttpService();
                    //新的请求包
                    IHttpRequestResponse requestResponse = null; //用于过if内的变量
                    JSONObject curstomParamJson = parseQueryStringToJson(curstomParam,paraList);
                   // IRequestInfo analyzeRequest = helpers.analyzeRequest(baseRequestResponse);
                    if(IRequestInfo.CONTENT_TYPE_JSON==contentType){
                        try {
                            /*****************获取body **********************/
                            int bodyOffset = analyzeRequest.getBodyOffset();
                            String request = new String(initRequest); //byte[] to String
                            String bodyJSONStr = request.substring(bodyOffset);
                            JSONObject bodyJson=JSONObject.parseObject(bodyJSONStr);
                            JSONObject newJson = CommonUtil.merge(bodyJson,curstomParamJson);
                            newRequest =helpers.buildHttpMessage( analyzeRequest.getHeaders(),newJson.toString().getBytes());
                        }catch (Exception e) {
                            continue;
                        }
                    }else {

                        byte paramType = analyzeRequest.getMethod().equals("GET")
                                ? IParameter.PARAM_URL
                                : IParameter.PARAM_BODY;
                        // 遍历 JSONObject 中的 key 和 value
                        for (Map.Entry<String, Object> entry : curstomParamJson.entrySet()) {
                            System.out.println("Key: " + entry.getKey() + ", Value: " + entry.getValue());
                            String key = entry.getKey();
                            String value = String.valueOf(entry.getValue());
                            IParameter param=helpers.buildParameter(key, value, paramType);
                            initRequest = helpers.addParameter(initRequest, param);
                        }
                        newRequest =initRequest;
                    }
                    time_1 = (int) System.currentTimeMillis();
                    requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);//发送请求
                    time_2 = (int) System.currentTimeMillis();
                    int newReposeLen = requestResponse.getResponse().length;
                    String change_sign = "";
                    if(newReposeLen!=original_data_len){
                        change_sign = "✔ ==> ?";
                        change_sign_1 = "✔";
                    }else{
                        //第一次包和第二次包的长度一样
                        change_sign = "";
                    }
                    log2.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(requestResponse),helpers.analyzeRequest(requestResponse).getUrl(),curstomParam,curstomParam,change_sign,temp_data,time_2-time_1,"end",helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                }

        }
        //用于更新是否已经跑完所有payload的状态
        for(int i = 0; i < log.size(); i++){
            if(temp_data.equals(log.get(i).data_md5)){
                log.get(i).setState("end!"+change_sign_1);
            }
        }

        //刷新第一个列表框
        BurpExtender.this.fireTableDataChanged();
        //第一个表格 继续选中之前选中的值
        BurpExtender.this.logTable.setRowSelectionInterval(BurpExtender.this.select_row,BurpExtender.this.select_row);



    }
    public static JSONObject parseQueryStringToJson(String curstomParam,List<IParameter> paraList) {
        Map<String, String> paramMap = paraList.stream()
                .collect(Collectors.toMap(
                        IParameter::getName,
                        p -> String.valueOf(p.getValue()),
                        (v1, v2) -> v1  // 保留第一个
                ));
        JSONObject json = new JSONObject();
        String[] pairs = curstomParam.split("&");

        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                String key = keyValue[0];
                String value = keyValue[1];
                //在插入额外参数之前，应该先校验原始参数是否包含某个额外的参数，如果存在，则以原始参数为准
                if(!paramMap.containsKey(key)){
                    // 判断是否为数字
                    if (value.matches("^\\d+$")) {
                        json.put(key, Integer.parseInt(value));
                    } else {
                        json.put(key, value);
                    }
                }
            }
        }

        return json;
    }


    public String execPlayLoad(IHttpRequestResponse baseRequestResponse,String key,String value,int toolFlag,String recoreMd5,byte paraType,String originalObj){

        String finalSign = "";
        int original_data_len = callbacks.saveBuffersToTempFiles(baseRequestResponse).getResponse().length;
        byte[] new_Request = baseRequestResponse.getRequest();
        //默认只开启 ["'","''"],常规单引号；["-0"，"-1"],单引号被过滤的情况
        String[] payloadplus={"[\"'\",\"''\"]","[\"-0\"，\"-1\"];;;[0-9]+"};
        //如果勾选了自定义payload，那么以自定义的为准
        if(JTextArea_int == 1&&StringUtils.isNotBlank(JTextArea_data_1)){
            payloadplus = JTextArea_data_1.split("\n");
        }

        for(String payloadSet:payloadplus){
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            //新的请求包
            IHttpRequestResponse requestResponse = null;
            String[] parts = payloadSet.split(";;;", 2); // Split into values and optional regex
            String valuesPart = parts[0]; // The JSON array part
            String regex = parts.length > 1 ? parts[1] : null; // Regex if present
            if (regex != null) {
                try {
                    if (!value.matches(regex)) {
                        // If the value doesn't match the regex, skip this payload
                        continue;
                    }
                } catch (PatternSyntaxException e) {
                    stdout.println("Invalid regex: " + regex);
                    continue; // Skip this payload if the regex is invalid
                }
            }
            if (regex != null&&!value.matches(regex)) {
                //如果值匹配不上就不用添加该playload
                continue;
            }
            // Parse the JSON array
            try {
                int change=0;
                int sleepTime = 0;
                //判断数据长度是否会变化
                String change_sign;//第二个表格中 变化 的内容
                JSONArray jsonArray = JSONArray.parseArray(valuesPart);
                for (int i = 0; i < jsonArray.size(); i++) {
                    int time_1 = 0,time_2 = 0;
                    String payload = jsonArray.getString(i); // Extract each value
                    stdout.println("payload: " + payload);
                    //判断payload是否存在sleep ,waitfor 等字段
                    if(jsonArray.size()==1&&(payload.contains("sleep")||payload.contains("waitfor"))){
                        //paylaod数组中只有一个值的时候并包含sleep ,waitfor 字符，判断为时间盲注
                        sleepTime=CommonUtil.getMaxNumberFromString(payload);
                        if(sleepTime<1){
                            break;
                        }
                    }
                    if(JTextArea_int == 1){
                        //自定义payload //参数值为空
                        if(diy_payload_2 == 1){
                            if(payload != "'" && payload !="''" && payload != "-1" && payload != "-0"){
                                value = "";
                            }
                        }
                    }
                    if(originalObj != null){
                        // 浅拷贝
                        JSONObject newObj=JSONObject.parseObject(originalObj);
                        //是json参数格式，替换对应key
                        String payloadStr=value+payload;
                       // CommonUtil.updateValueByPath(newObj, key, payloadStr);
                        JSONPath.set(newObj,"$"+key,payloadStr);
                        byte[] newRequest =helpers.buildHttpMessage( helpers.analyzeRequest(baseRequestResponse).getHeaders(),newObj.toString().getBytes());
                        time_1 = (int) System.currentTimeMillis();
                        requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);//发送请求
                        time_2 = (int) System.currentTimeMillis();
                    }else {
                        stdout.println("普通格式");
                        //不是json格式
                        IParameter newPara = helpers.buildParameter(key,value + payload, paraType); //构造新的参数
                        byte[] newRequest = helpers.updateParameter(new_Request, newPara);//更新请求包的参数

                        time_1 = (int) System.currentTimeMillis();
                        requestResponse = callbacks.makeHttpRequest(iHttpService, newRequest);//发送请求
                        time_2 = (int) System.currentTimeMillis();

                    }

                    if(i==0){
                        change = requestResponse.getResponse().length;//保存第一次请求响应的长度
                        change_sign = "";
                    }else {
                        if(change != requestResponse.getResponse().length){//判断第一次的长度和现在的是否不同
                            if( requestResponse.getResponse().length == original_data_len ){
                                //判断两个payload的长度不一样且和原始包的长度一致,存疑！
                                change_sign = "✔ ==> ?";
                                finalSign = "✔";
                            }else{
                                //判断两个payload的长度不一样，判断为存在安全风险
                                change_sign = "✔ "+ (change-requestResponse.getResponse().length);
                                finalSign = "✔";
                            }
                        }else {
                            //第一次包和第二次包的长度一样
                            change_sign = "";
                        }
                    }
                    if(jsonArray.size()==1){
                        //只有一个payload的情况下
                        if(sleepTime>0){
                            //时间盲注
                            if ((time_2 - time_1) > (sleepTime)*1000) {
                                //响应应时间 大于payload的值
                                change_sign = "✔ ==> ?";
                                finalSign = "✔";
                            } else {
                                change_sign = "";
                            }
                        }else {
                            //,普通注入，直接跟原始返回大小比对，如果不同，设为存疑
                            if(change!=original_data_len){
                                change_sign = "✔ ==> ?";
                                finalSign = "✔";
                            }else{
                                //第一次包和第二次包的长度一样
                                change_sign = "";
                            }
                        }

                    }
                    log2.add(new LogEntry(conut,toolFlag, callbacks.saveBuffersToTempFiles(requestResponse),helpers.analyzeRequest(requestResponse).getUrl(),key,value+payload,change_sign,recoreMd5,time_2-time_1,"end",helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode()));
                }
            } catch (JSONException e) {
                stdout.println("Error parsing JSON: " + e.getMessage());
            }
        }
        return finalSign;
    }
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();

    }

    @Override
    public int getColumnCount()
    {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "#";
            case 1:
                return "来源";
            case 2:
                return "URL";
            case 3:
                return "返回包长度";
            case 4:
                return "状态";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.id;
            case 1:
                return callbacks.getToolName(logEntry.tool);
            case 2:
                return logEntry.url.toString();
            case 3:
                return logEntry.requestResponse.getResponse().length;//返回响应包的长度
            case 4:
                return logEntry.state;
            default:
                return "";
        }
    }


    //model2
    class MyModel extends AbstractTableModel {

        @Override
        public int getRowCount()
        {
            return log3.size();
        }

        @Override
        public int getColumnCount()
        {
            return 6;
        }

        @Override
        public String getColumnName(int columnIndex)
        {
            switch (columnIndex)
            {
                case 0:
                    return "参数";
                case 1:
                    return "payload";
                case 2:
                    return "返回包长度";
                case 3:
                    return "变化";
                case 4:
                    return "用时";
                case 5:
                    return "响应码";
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex)
        {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex)
        {
            LogEntry logEntry2 = log3.get(rowIndex);

            switch (columnIndex)
            {
                case 0:
                    return logEntry2.parameter;
                case 1:
                    return logEntry2.value;
                case 2:
                    return logEntry2.requestResponse.getResponse().length;//返回响应包的长度
                case 3:
                    return logEntry2.change;
                case 4:
                    return logEntry2.times;
                case 5:
                    return logEntry2.response_code;
                default:
                    return "";
            }
        }
    }




    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            data_md5_id = logEntry.data_md5;
            //stdout.println(log_id);//输出目前选中的行数
            select_row = logEntry.id;

            log3.clear();
            for (int i = 0; i < log2.size(); i++) {//筛选出目前选中的原始数据包--》衍生出的带有payload的数据包
                 if(log2.get(i).data_md5==data_md5_id){
                     log3.add(log2.get(i));
                 }
            }
            //刷新列表界面
            model.fireTableRowsInserted(log3.size(), log3.size());
            model.fireTableDataChanged();

            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class Table_log2 extends JTable
    {
        public Table_log2(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {

            // show the log entry for the selected row
            LogEntry logEntry = log3.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

    //存放数据包的md5值，用于匹配该数据包已请求过
    private static class Request_md5
    {
        final String md5_data;

        Request_md5(String md5_data)
        {
            this.md5_data = md5_data;
        }
    }
    //
    // class to hold details of each log entry
    //
    private static class LogEntry
    {
        final int id;
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;
        final String parameter;
        final String value;
        final String change;
        final String data_md5;
        final int times;
        final int response_code;
        String state;


        LogEntry(int id,int tool, IHttpRequestResponsePersisted requestResponse, URL url,String parameter,String value,String change,String data_md5,int times,String state,int response_code)
        {
            this.id = id;
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
            this.parameter = parameter;
            this.value = value;
            this.change = change;
            this.data_md5 = data_md5;
            this.times = times;
            this.state = state;
            this.response_code = response_code;
        }

        public String setState(String state){
            this.state = state;
            return this.state;
        }
    }

    public static String MD5(String key) {
        char hexDigits[] = {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };
        try {
            byte[] btInput = key.getBytes();
            // 获得MD5摘要算法的 MessageDigest 对象
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            // 使用指定的字节更新摘要
            mdInst.update(btInput);
            // 获得密文
            byte[] md = mdInst.digest();
            // 把密文转换成十六进制的字符串形式
            int j = md.length;
            char str[] = new char[j * 2];
            int k = 0;
            for (int i = 0; i < j; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            return null;
        }
    }


}
