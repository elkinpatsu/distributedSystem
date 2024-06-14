package main;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

public class distributedSystem extends JFrame {
    private static JButton switchButton;
    private static List<PrintWriter> clientes;
    private JButton estresButton;
    private static Socket socket;
    private static PrintWriter out;
    private static BufferedReader in;
    private static ServerSocket serverSocket;
    private static List<PrintWriter> clients = new ArrayList<>();
    private static List<Socket> clientSockets = new ArrayList<>();
    private static ArrayList<String[]> DataClients = new ArrayList<>();
    private static String clientIP = "25.53.178.157";
    private static DefaultTableModel tableModel;
    private JTable table;
    private Timer timer;
    private static boolean isServerMode = true; // Inicia en modo servidor
    private static ScheduledExecutorService executor;
    private static String[] serverIPs = {"25.57.124.131", "25.13.41.150", "25.53.178.157", "25.53.225.158", "25.42.108.158"}; // Lista de direcciones IP del servidor
    private static int currentServerIndex = 0;
    private static ScheduledExecutorService metricSenderExecutor;
    private static String[] metricasEstaticas = new String[6]; 
    private JTable detailedTable;
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static DefaultTableModel detailedModel;
    private static int numNucleos = 4;
    private static int hacerSwitch = 0;
    private static int stressLevel = 0;
    private static OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
    private static boolean connected = false;
    private static final String IP_REGEX = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
            + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
            + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
            + "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
    private static final Pattern IP_PATTERN = Pattern.compile(IP_REGEX);

    public static void main(String[] args) throws InterruptedException {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        Runnable connectionChecker = new Runnable() {
            public void run() {
                if (isServerAvailable(clientIP, 9999, 3000)) {
                    System.out.println("Servidor está en línea.");
                } else {
                    System.out.println("Servidor está fuera de línea.");
                    reconnectToNextServer();
                }
            }
        };

        if (args.length > 0) {
            clientIP = args[0];
        } else {
            clientIP = "25.53.178.157"; // IP predeterminada si no se proporciona ninguna
        }

        SwingUtilities.invokeLater(() -> {	
            distributedSystem node = new distributedSystem(clientes);
            node.setVisible(true);
            //distributedSystem.switchToServer();
        });
                
        scheduler.scheduleAtFixedRate(connectionChecker, 0, 10, TimeUnit.SECONDS);


        Thread.sleep(500);
        startMetricUpdateTask();
    }

    public static void switchToServer() {
        try {
            switchMode();
        } catch (IOException ex) {
            ex.printStackTrace();
        }    	
    }
    
    public distributedSystem(List <PrintWriter> clientes) {
        super("Network Node");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1200, 600);
        setupUI();
        distributedSystem.clientes = clientes;
        if (isServerMode) {
            try {
                startServer();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                startClient(clientIP, 9999);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    private static void broadcastMessage() throws InterruptedException {
        for (PrintWriter client : clients) {
        	if (client != null) {
            	System.out.println("Valid IP?: "+isValidIP(tableModel.getValueAt(0, 0)+""));
            	if (isValidIP(tableModel.getValueAt(0, 0)+"")) {
            		client.println(tableModel.getValueAt(0, 0));
            		if (!tableModel.getValueAt(0, 0).equals(getHamachiIP())) {
            			client.println(tableModel.getValueAt(0, 0));
            			switchToServer();
            		}
            	}
            }
        }
    }
    
    
    private void setupUI() {
        JPanel panel = new JPanel();
        add(panel);

        switchButton = new JButton("Switch to Client");
        switchButton.addActionListener(e -> {
            try {
                switchMode();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        //panel.add(switchButton);
        
        estresButton = new JButton("Generar estres");
        estresButton.addActionListener(e -> {
            metricSenderExecutor = Executors.newSingleThreadScheduledExecutor();
            metricSenderExecutor.scheduleAtFixedRate(() -> {
                if (out != null) {
                    out.println("STRESS");
                }
            }, 0, 1, TimeUnit.SECONDS);
        });
        panel.add(estresButton);


        // Table for server mode
        String[] columns = {"IP", "CPU FREE(%)", "MEMORY FREE(%)", "DISK FREE(%)", "RANKSCORE", "BANDWIDTH", "STATUS"};
        tableModel = new DefaultTableModel(columns, 0);
        table = new JTable(tableModel);
        
        // Crear el modelo de la tabla para información detallada
        String[] detailedColumnNames = { "dispositivo",
            "Procesador", "Velocidad", "Nucleos", "Almacenamiento",
            "OSVersion"
            };

        Object[] row1 = {
                System.getProperty("user.name"), getSystemInfo("wmic cpu get name"), getSystemInfo("wmic cpu get MaxClockSpeed"),
                Runtime.getRuntime().availableProcessors(), new File("/").getTotalSpace() / (1024 * 1024 * 1024) + " GB",
                getSystemInfo("wmic os get Version")
            };
        
        metricasEstaticas[0] = System.getProperty("user.name");
        metricasEstaticas[1] = getSystemInfo("wmic cpu get name");
        metricasEstaticas[2] = getSystemInfo("wmic cpu get MaxClockSpeed")+"MHz";
        metricasEstaticas[3] = Runtime.getRuntime().availableProcessors()+"";
        File disk = new File("C:");
        long totalSpace = disk.getTotalSpace();
        metricasEstaticas[4] = formatSize(totalSpace);
        metricasEstaticas[5] = System.getProperty("os.version");
        
        

        detailedModel = new DefaultTableModel(detailedColumnNames, 0);
        
        detailedModel.addRow(row1);

        detailedTable = new JTable(detailedModel);
        JScrollPane detailedScrollPane = new JScrollPane(detailedTable);

        // Crear un panel para las tablas y agregar las tablas al panel
        JPanel tablePanel = new JPanel(new GridLayout(2, 1)); // 2 filas, 1 columna
        tablePanel.add(detailedScrollPane);

        
        panel.add(new JScrollPane(table));
        panel.add(new JScrollPane(detailedTable));
    }
    
    private static String formatSize(long size) {
        long gb = 1024L * 1024L * 1024L;
        return size / gb + " GB";
    }

    
    private String getSystemInfo(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty() && !line.contains("Name") && !line.contains("MaxClockSpeed") && !line.contains("Version")) {
                    return line.trim();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "Unknown";
    }


    private static void switchMode() throws IOException {
        if (isServerMode) {
            // Modo servidor a cliente
            //notifyClientsToSwitch(clientIP);
            stopServer();
            resetTable();
            startClient(clientIP, 9999);
            switchButton.setText("Switch to Server");
            isServerMode = false;
            startSendingMetrics();
        } else {
            // Modo cliente a servidor
            notifyServerSwitching();
            stopClient();
            startServer();
            resetTable();
            switchButton.setText("Switch to Client");
            isServerMode = true;
            stopSendingMetrics();
        }
    }

    private static void notifyServerSwitching() throws IOException {
        if (out != null) {
            out.println("SWITCHING_TO_SERVER " + socket.getLocalAddress().getHostAddress());
        }
    }

    private void notifyClientsToSwitch(String newServerIP) {
        for (PrintWriter client : clients) {
            client.println("SWITCH_TO_NEW_SERVER " + newServerIP);
        }
    }

    private static void startServer() throws IOException {
        serverSocket = new ServerSocket(9999);
        executor = Executors.newScheduledThreadPool(10);
        executor.scheduleAtFixedRate(() -> {
            try {
                Socket clientSocket = serverSocket.accept();
                clientSockets.add(clientSocket);
                PrintWriter clientOut = new PrintWriter(clientSocket.getOutputStream(), true);
                clients.add(clientOut);
                new Thread(new ClientHandler(clientSocket)).start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }, 0, 1, TimeUnit.SECONDS);
    }

    public static boolean isValidIP(String ip) {
        if (ip == null) {
            return false;
        }
        Matcher matcher = IP_PATTERN.matcher(ip);
        return matcher.matches();
    }
    
    private static void stopServer() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
            for (Socket clientSocket : clientSockets) {
                clientSocket.close();
            }
            clients.clear();
            clientSockets.clear();
            executor.shutdown();
        }
    }

    private static void startClient(String serverIP, int port) throws IOException {
        try {
            socket = new Socket(serverIP, port);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            connected = true;
            new Thread(() -> {
                try {
                    String message;
                    while ((message = in.readLine()) != null) {
                        processServerMessage(message);
                    }
                } catch (IOException e) {
                    reconnectToNextServer();
                }
            }).start();
        } catch (IOException e) {
            reconnectToNextServer();
        }
    }

    private static void stopClient() throws IOException {
        if (socket != null) {
            socket.close();
            out.close();
            in.close();
            connected = false;
        }
    }

    private static void reconnectToNextServer() {
        currentServerIndex = (currentServerIndex + 1) % serverIPs.length;
        String nextServerIP = serverIPs[currentServerIndex];
        try {
            startClient(nextServerIP, 9999);
        } catch (IOException e) {
            e.printStackTrace();
            reconnectToNextServer(); // Reintenta con la siguiente IP
        }
    }

    private static void processServerMessage(String message) {
    	System.out.println(message+":"+getHamachiIP()+""+message.trim().equals(getHamachiIP()));
    	if (message.trim().equals(getHamachiIP()) && !isServerMode) {
    		switchToServer();
    	}
        if (message.startsWith("SWITCH_TO_NEW_SERVER")) {
            String[] parts = message.split(" ");
            if (parts.length == 2) {
                String newServerIP = parts[1];
                switchToNewServer(newServerIP);
            }
        } else if (message.startsWith("STRESS")) {
            arrancaEstres();
        }
    }

    private static void switchToNewServer(String newServerIP) {
        try {
            stopClient();
            startClient(newServerIP, 9999);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean isServerAvailable(String ip, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    private static void startSendingMetrics() {
        metricSenderExecutor = Executors.newSingleThreadScheduledExecutor();
        metricSenderExecutor.scheduleAtFixedRate(() -> {
            if (out != null) {
                out.println(updateSystemMetrics());
            }
        }, 0, 1, TimeUnit.SECONDS);
    }

    private static void stopSendingMetrics() {
        if (metricSenderExecutor != null) {
            metricSenderExecutor.shutdown();
        }
    }

    public static String getHamachiIP() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (networkInterface.isUp() && !networkInterface.isLoopback()) {
                    if (networkInterface.getDisplayName().contains("Hamachi")) {
                        Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                        while (addresses.hasMoreElements()) {
                            InetAddress address = addresses.nextElement();
                            if (address.getAddress().length == 4) { // Check if it's IPv4
                                return address.getHostAddress();
                            }
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static void startMetricUpdateTask() {
        scheduler.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                String metrics = updateSystemMetrics();
                
                try {
					processClientData(metrics.split("-")[0].split(","),metrics.split("-")[1].split(","));
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
        }, 0, 1, TimeUnit.MICROSECONDS); // Actualiza cada 10 segundos
    }
    
    public static double bandwidthTest() throws IOException {
        // Definir el comando PowerShell
        String command = "powershell.exe -Command $size=0.015KB;$url='https://speed.hetzner.de/100MB.bin';$duration=(Measure-Command{Invoke-WebRequest-Uri $url-OutFile $env:TEMP\\testfile.bin}).TotalSeconds;$bandwidthMBps=$size/$duration;[Console]::WriteLine($bandwidthMBps)";

        // Ejecutar el comando
        Process process = Runtime.getRuntime().exec(command);

        // Leer la salida del comanedo
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        double bandwidth = 0.0;
        while ((line = reader.readLine()) != null) {
            try {
                bandwidth = Double.parseDouble(line.trim());
            } catch (NumberFormatException e) {
                // Si no es un número, ignorar
            }
        }

        // Esperar a que el proceso termine
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Retornar el ancho de banda
        return bandwidth;

    }


    private static String updateSystemMetrics() {         
        OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        double cpuLoad = osBean.getSystemCpuLoad() * 100;
        double cpuFree = 100 - cpuLoad;
        long freePhysicalMemorySize = osBean.getFreePhysicalMemorySize();
        long totalPhysicalMemorySize = osBean.getTotalPhysicalMemorySize();
        double memoryFreePercentage = (double) freePhysicalMemorySize / totalPhysicalMemorySize * 100;
        File disk = new File("/");
        long freeDiskSpace = disk.getFreeSpace();
        long totalDiskSpace = disk.getTotalSpace();
        double diskFreePercentage = (double) freeDiskSpace / totalDiskSpace * 100;
        double rankScore = ((cpuFree + memoryFreePercentage + diskFreePercentage + numNucleos * 100) / 100)-stressLevel;
        String bandwidth = null;
        try {
            bandwidth = (bandwidthTest())+"MB/s";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return getHamachiIP() + "," + cpuFree + "," + memoryFreePercentage + "," + diskFreePercentage + "," + rankScore + "," + bandwidth + ",false"+"-"+metricasEstaticas[0]+","+metricasEstaticas[1]+","+metricasEstaticas[2]+","+metricasEstaticas[3]+","+metricasEstaticas[4]+","+metricasEstaticas[5]+",";
    }

    private static void addMetricsToTable(String[] metrics, String[] staticMetrics) throws IOException {
        SwingUtilities.invokeLater(() -> {
            boolean updated = false;
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                boolean active = !(tableModel.getValueAt(i, 2).equals(metrics[2]) && tableModel.getValueAt(i, 3).equals(metrics[3]) && tableModel.getValueAt(i, 4).equals(metrics[4]));
                if (!active) {
                    tableModel.setValueAt("Desconectado", i, 6);
                } else {
                    tableModel.setValueAt("Conectado", i, 6);
                }
                if (tableModel.getValueAt(i, 0).equals(metrics[0])) {
                    tableModel.setValueAt(metrics[1], i, 1);
                    tableModel.setValueAt(metrics[2], i, 2);
                    tableModel.setValueAt(metrics[3], i, 3);
                    tableModel.setValueAt(metrics[4], i, 4);
                    tableModel.setValueAt(metrics[5], i, 5);
                    detailedModel.setValueAt(staticMetrics[0], i, 0);
                    detailedModel.setValueAt(staticMetrics[1], i, 1);
                    detailedModel.setValueAt(staticMetrics[2], i, 2);
                    detailedModel.setValueAt(staticMetrics[3], i, 3);
                    detailedModel.setValueAt(staticMetrics[4], i, 4);
                    detailedModel.setValueAt(staticMetrics[5], i, 5);
                    updated = true;
                    break;
                }
            }
            if (!updated) {
                tableModel.addRow(metrics);
            }
            updated = false;
            for (int i = 0; i < detailedModel.getRowCount(); i++) {
                if (detailedModel.getValueAt(i, 0).equals(staticMetrics[0])) {
                    updated = true;
                    break;
                }
            }
            if (!updated) {
                detailedModel.addRow(staticMetrics);
            }

            sortTableByRankScore();
            try {
				broadcastMessage();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        });
    }
    
    static void arrancaEstres() {
        System.out.println("-------- SE ARRANCA PRUEBAS DE ESTRES --------");
        
        List<byte[]> memoryList = new ArrayList<>();
        stressLevel += 1 + (Math.random() * (5 - 1));

        boolean stressFlag = true;

        while(stressFlag){
            try{
                //Carga de CPU
                for(int i=0;i<100;i++){
                    Math.atan(Math.sqrt(Math.pow(Math.random()*i,2)));
                    Math.atan(Math.sqrt(Math.pow(Math.random()*i,2)));
                }

                byte[] memoryChunk = new byte[1024*1024*(10)]; //5MB
                memoryList.add(memoryChunk);

            }catch(OutOfMemoryError e){
                System.err.println("Error: Se ha agotado la memoria disponible");
                memoryList= new ArrayList<>();
                stressFlag=false;
            }
        }
    }

    private static void sortTableByRankScore() {
        List<String[]> tableData = new ArrayList<>();
        List<String[]> tableStaticData = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String[] row = new String[tableModel.getColumnCount()];
            String[] row2 = new String[detailedModel.getColumnCount()];
            for (int j = 0; j < tableModel.getColumnCount(); j++) {
                row[j] = tableModel.getValueAt(i, j).toString();
            }
            for (int j = 0; j < detailedModel.getColumnCount(); j++) {
                row2[j] = detailedModel.getValueAt(i, j).toString();
            }
            tableData.add(row);
            tableStaticData.add(row2);
        }
        
        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < tableData.size(); i++) {
            indices.add(i);
        }

        // Ordenar los índices basándose en tableData
        Collections.sort(indices, new Comparator<Integer>() {
            @Override
            public int compare(Integer index1, Integer index2) {
                return Double.compare(Double.parseDouble(tableData.get(index2)[4]), Double.parseDouble(tableData.get(index1)[4]));
            }
        });

        // Aplicar la ordenación a ambos arreglos usando los índices ordenados
        List<String[]> sortedTableData = new ArrayList<>();
        List<String[]> sortedTableStaticData = new ArrayList<>();

        for (int index : indices) {
            sortedTableData.add(tableData.get(index));
            sortedTableStaticData.add(tableStaticData.get(index));
        }

        tableModel.setRowCount(0); // Clear the table
        detailedModel.setRowCount(0); // Clear the table
        for (String[] row : sortedTableData) {
            tableModel.addRow(row);
        }
        
        for (String[] row : sortedTableStaticData) {
            detailedModel.addRow(row);
        }
        
    }

    private static void resetTable() {
        SwingUtilities.invokeLater(() -> tableModel.setRowCount(0));
        SwingUtilities.invokeLater(() -> detailedModel.setRowCount(0));
    }

    private static class ClientHandler implements Runnable {
        private Socket socket;
        private BufferedReader in;
        private Timer timer;

        public ClientHandler(Socket socket) {
            this.socket = socket;
            try {
                this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            } catch (IOException e) {
                e.printStackTrace();
            }
            this.timer = new Timer();
            resetTimer();
        }

        @Override
        public void run() {
            try {
                String message;
                while ((message = in.readLine()) != null) {
                    resetTimer();
                	System.out.println(message+":"+(message.trim() == getHamachiIP()));
                	if (message.trim() == getHamachiIP()) {
                		switchToServer();
                	}
                	if (message.startsWith("STRESS")) {
                        arrancaEstres();
                    }
                    if (message.equals("SWITCH_TO_SERVER")) {
                        SwingUtilities.invokeLater(() -> {
                            try {
                                switchMode();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        });
                    } else {
                        processClientData(message.split("-")[0].split(","),message.split("-")[1].split(","));
                    }
                }
            } catch (IOException e) {
                //e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    //e.printStackTrace();
                }
                clients.remove(socket);
            }
        }

        private void resetTimer() {
            timer.cancel();
            timer = new Timer();
            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    markClientAsNull();
                }
            }, 3000);
        }
        
        private void markClientAsNull() {
            SwingUtilities.invokeLater(() -> {
                if (!clients.isEmpty()) {
                    clients.set(clients.size() - 1, null);
                }
            });
        }

        private void processClientData(String[] clientData, String[] clientStaticData) throws IOException {
            if (clientData.length == 7) {
                addMetricsToTable(clientData, clientStaticData);
            }
        }
    }
    private static void processClientData(String[] clientData, String[] clientStaticData) throws IOException {
        if (clientData.length == 7) {
            addMetricsToTable(clientData, clientStaticData);
        }
    }

}